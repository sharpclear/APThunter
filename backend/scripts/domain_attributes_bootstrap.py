#!/usr/bin/env python3
"""
系统启动后自动补全域名属性（WHOIS / DNS / SSL）

用途：
- 针对 domains 表中尚未具备 whois_info / dns_records / ssl_certificates 的域名
- 自动进行实时查询并入库，供 dashboard/attributes 页面直接展示

特性：
- 并发执行，支持 limit 控制
- 查询失败不阻塞整体流程
- 以增量方式写入（只补缺失项）
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import date, datetime
from typing import Any

import dns.resolver
import whois
from sqlalchemy import create_engine, text

MYSQL_URL = os.getenv("MYSQL_URL", "mysql+pymysql://apthunter:4CyUhr2zu6!@mysql:3306/apthunter_new")


def safe_str(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, (list, tuple)):
        return str(value[0]) if value else None
    return str(value)


def safe_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value if v is not None]
    return [str(value)]


def parse_to_date(value: Any) -> date | None:
    if value is None:
        return None
    if isinstance(value, list) and value:
        value = value[0]
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value

    s = str(value).strip()
    if not s:
        return None

    for fmt in ("%Y-%m-%d", "%Y/%m/%d", "%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%d-%b-%Y"):
        try:
            return datetime.strptime(s, fmt).date()
        except Exception:
            pass

    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).date()
    except Exception:
        return None


def parse_cert_datetime(value: Any) -> datetime | None:
    if value is None:
        return None
    s = str(value).strip()
    if not s:
        return None

    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y"):
        try:
            return datetime.strptime(s, fmt)
        except Exception:
            pass

    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return None


def lookup_whois(domain: str) -> dict[str, Any] | None:
    data = whois.whois(domain)
    registrant = {}
    if getattr(data, "name", None):
        registrant["name"] = safe_str(data.name)
    if getattr(data, "org", None):
        registrant["organization"] = safe_str(data.org)
    if getattr(data, "country", None):
        registrant["country"] = safe_str(data.country)
    if getattr(data, "email", None):
        registrant["email"] = safe_str(data.email)
    if getattr(data, "address", None):
        registrant["address"] = safe_str(data.address)

    result = {
        "registrar": safe_str(getattr(data, "registrar", None)),
        "registration_date": parse_to_date(getattr(data, "creation_date", None)),
        "expiration_date": parse_to_date(getattr(data, "expiration_date", None)),
        "updated_date": parse_to_date(getattr(data, "updated_date", None)),
        "name_servers": safe_list(getattr(data, "name_servers", None)),
        "registrant": registrant if registrant else None,
        "status": safe_list(getattr(data, "status", None)),
    }

    if not any([result["registrar"], result["name_servers"], result["registrant"], result["status"]]):
        return None
    return result


def lookup_dns(domain: str, lifetime: float) -> list[dict[str, Any]]:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = lifetime
    resolver.timeout = min(3.0, lifetime)

    records: list[dict[str, Any]] = []
    for record_type in ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]:
        try:
            answers = resolver.resolve(domain, record_type)
            ttl = answers.rrset.ttl if answers.rrset else None
            for rdata in answers:
                if record_type == "MX":
                    value = str(rdata.exchange).rstrip(".")
                    priority = int(getattr(rdata, "preference", 0) or 0)
                elif record_type == "SOA":
                    value = f"{rdata.mname} {rdata.rname}"
                    priority = None
                else:
                    value = str(rdata).rstrip(".")
                    priority = None

                records.append(
                    {
                        "record_type": record_type,
                        "record_name": domain,
                        "record_value": value,
                        "ttl": ttl,
                        "priority": priority,
                    }
                )
        except Exception:
            continue

    return records


def lookup_ssl(domain: str, timeout: float) -> dict[str, Any] | None:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with socket.create_connection((domain, 443), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=domain) as ssock:
            cert = ssock.getpeercert()

    issuer = {}
    for item in cert.get("issuer", []):
        for k, v in item:
            issuer[k] = v

    subject = {}
    for item in cert.get("subject", []):
        for k, v in item:
            subject[k] = v

    san_names = [name for t, name in cert.get("subjectAltName", []) if t == "DNS"]

    return {
        "issuer": issuer or None,
        "subject": subject or None,
        "serial_number": cert.get("serialNumber"),
        "not_before": parse_cert_datetime(cert.get("notBefore")),
        "not_after": parse_cert_datetime(cert.get("notAfter")),
        "san_names": san_names or None,
        "is_expired": False,
        "is_self_signed": issuer == subject if issuer and subject else False,
    }


def insert_results(engine, domain_id: int, whois_data, dns_records, cert_data, need_whois: bool, need_dns: bool, need_ssl: bool):
    wrote_whois = 0
    wrote_dns = 0
    wrote_ssl = 0

    with engine.begin() as conn:
        if need_whois and whois_data:
            conn.execute(
                text(
                    """
                    INSERT INTO whois_info (
                        domain_id, registrar, registration_date, expiration_date,
                        updated_date, name_servers, registrant, admin, tech, status, query_time
                    ) VALUES (
                        :domain_id, :registrar, :registration_date, :expiration_date,
                        :updated_date, :name_servers, :registrant, NULL, NULL, :status, NOW()
                    )
                    """
                ),
                {
                    "domain_id": domain_id,
                    "registrar": whois_data.get("registrar"),
                    "registration_date": whois_data.get("registration_date"),
                    "expiration_date": whois_data.get("expiration_date"),
                    "updated_date": whois_data.get("updated_date"),
                    "name_servers": json.dumps(whois_data.get("name_servers") or []),
                    "registrant": json.dumps(whois_data.get("registrant")) if whois_data.get("registrant") else None,
                    "status": json.dumps(whois_data.get("status") or []),
                },
            )
            wrote_whois = 1

        if need_dns and dns_records:
            for record in dns_records:
                conn.execute(
                    text(
                        """
                        INSERT INTO dns_records (
                            domain_id, record_type, record_name, record_value, ttl, priority
                        ) VALUES (
                            :domain_id, :record_type, :record_name, :record_value, :ttl, :priority
                        )
                        """
                    ),
                    {
                        "domain_id": domain_id,
                        "record_type": record["record_type"],
                        "record_name": record["record_name"],
                        "record_value": record["record_value"],
                        "ttl": record.get("ttl"),
                        "priority": record.get("priority"),
                    },
                )
            wrote_dns = len(dns_records)

        if need_ssl and cert_data:
            conn.execute(
                text(
                    """
                    INSERT INTO ssl_certificates (
                        domain_id, issuer, subject, serial_number, not_before, not_after,
                        san_names, is_expired, is_self_signed, created_at
                    ) VALUES (
                        :domain_id, :issuer, :subject, :serial_number, :not_before, :not_after,
                        :san_names, :is_expired, :is_self_signed, NOW()
                    )
                    """
                ),
                {
                    "domain_id": domain_id,
                    "issuer": json.dumps(cert_data.get("issuer")) if cert_data.get("issuer") else None,
                    "subject": json.dumps(cert_data.get("subject")) if cert_data.get("subject") else None,
                    "serial_number": cert_data.get("serial_number"),
                    "not_before": cert_data.get("not_before"),
                    "not_after": cert_data.get("not_after"),
                    "san_names": json.dumps(cert_data.get("san_names")) if cert_data.get("san_names") else None,
                    "is_expired": bool(cert_data.get("is_expired", False)),
                    "is_self_signed": bool(cert_data.get("is_self_signed", False)),
                },
            )
            wrote_ssl = 1

    return wrote_whois, wrote_dns, wrote_ssl


def process_one(engine, row, timeout: float):
    domain_id, domain_name, has_whois, has_dns, has_ssl = row
    need_whois = int(has_whois or 0) == 0
    need_dns = int(has_dns or 0) == 0
    need_ssl = int(has_ssl or 0) == 0

    whois_data = None
    dns_data = None
    ssl_data = None
    errors = []

    if need_whois:
        try:
            whois_data = lookup_whois(domain_name)
        except Exception as e:
            errors.append(f"WHOIS:{e}")

    if need_dns:
        try:
            dns_data = lookup_dns(domain_name, lifetime=timeout)
        except Exception as e:
            errors.append(f"DNS:{e}")

    if need_ssl:
        try:
            ssl_data = lookup_ssl(domain_name, timeout=timeout)
        except Exception as e:
            errors.append(f"SSL:{e}")

    wrote = (0, 0, 0)
    if any([whois_data, dns_data, ssl_data]):
        try:
            wrote = insert_results(engine, domain_id, whois_data, dns_data, ssl_data, need_whois, need_dns, need_ssl)
        except Exception as e:
            errors.append(f"DB:{e}")

    return wrote, errors


def main():
    parser = argparse.ArgumentParser(description="auto bootstrap domain attributes")
    parser.add_argument("--workers", type=int, default=int(os.getenv("DOMAIN_BOOTSTRAP_WORKERS", "8")))
    parser.add_argument("--timeout", type=float, default=float(os.getenv("DOMAIN_BOOTSTRAP_TIMEOUT", "6")))
    parser.add_argument("--limit", type=int, default=int(os.getenv("DOMAIN_BOOTSTRAP_LIMIT", "0")))
    args = parser.parse_args()

    engine = create_engine(MYSQL_URL, pool_pre_ping=True)

    print("[domain-bootstrap] start")
    print(f"[domain-bootstrap] workers={args.workers}, timeout={args.timeout}, limit={args.limit}")

    with engine.connect() as conn:
        rows = conn.execute(
            text(
                """
                SELECT
                    d.id,
                    d.domain_name,
                    (SELECT COUNT(*) FROM whois_info w WHERE w.domain_id = d.id) AS has_whois,
                    (SELECT COUNT(*) FROM dns_records r WHERE r.domain_id = d.id) AS has_dns,
                    (SELECT COUNT(*) FROM ssl_certificates s WHERE s.domain_id = d.id) AS has_ssl
                FROM domains d
                ORDER BY d.id
                """
            )
        ).fetchall()

    targets = [r for r in rows if int(r[2] or 0) == 0 or int(r[3] or 0) == 0 or int(r[4] or 0) == 0]
    if args.limit > 0:
        targets = targets[: args.limit]

    total = len(targets)
    print(f"[domain-bootstrap] pending domains={total}")
    if total == 0:
        print("[domain-bootstrap] nothing to do")
        return

    done = 0
    whois_cnt = 0
    dns_cnt = 0
    ssl_cnt = 0
    fail_cnt = 0

    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
        futures = [pool.submit(process_one, engine, r, args.timeout) for r in targets]
        for fu in as_completed(futures):
            (w1, w2, w3), errs = fu.result()
            done += 1
            whois_cnt += w1
            dns_cnt += w2
            ssl_cnt += w3
            if errs and w1 == 0 and w2 == 0 and w3 == 0:
                fail_cnt += 1

            if done % 20 == 0 or done == total:
                print(
                    f"[domain-bootstrap] {done}/{total} | whois+={whois_cnt}, dns+={dns_cnt}, ssl+={ssl_cnt}, fail={fail_cnt}"
                )

    print("[domain-bootstrap] done")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        # 不阻断部署流程
        print(f"[domain-bootstrap] fatal but ignored: {e}")
