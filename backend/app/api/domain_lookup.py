"""
域名实时查询API
提供WHOIS、DNS、SSL证书等信息的实时查询服务
"""
from fastapi import APIRouter, Body
from fastapi.responses import JSONResponse
from sqlalchemy import text
from pydantic import BaseModel
from typing import Optional, Dict, List, Any
import whois
import dns.resolver
import ssl
import socket
import json
from datetime import datetime
from app.db.session import engine

router = APIRouter(prefix="/api/domain", tags=["domain-lookup"])


class DomainLookupRequest(BaseModel):
    domain: str
    save: bool = False  # 是否保存到数据库


def safe_str(value) -> Optional[str]:
    """安全地转换值为字符串"""
    if value is None:
        return None
    if isinstance(value, (list, tuple)) and value:
        return str(value[0]) if value else None
    return str(value)


def safe_list(value) -> List[str]:
    """安全地转换值为列表"""
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value]
    return [str(value)]


@router.post("/lookup/whois")
def lookup_whois(request: DomainLookupRequest = Body(...)):
    """实时查询 WHOIS 信息"""
    domain = request.domain.strip()
    
    if not domain:
        return JSONResponse(
            status_code=400,
            content={"code": 400, "msg": "域名不能为空", "data": None}
        )
    
    try:
        w = whois.whois(domain)
        
        # 提取注册人信息
        registrant = {}
        if hasattr(w, 'name') and w.name:
            registrant['name'] = safe_str(w.name)
        if hasattr(w, 'org') and w.org:
            registrant['organization'] = safe_str(w.org)
        if hasattr(w, 'country') and w.country:
            registrant['country'] = safe_str(w.country)
        if hasattr(w, 'email') and w.email:
            registrant['email'] = safe_str(w.email)
        if hasattr(w, 'address') and w.address:
            registrant['address'] = safe_str(w.address)
        
        data = {
            "domain": domain,
            "registrar": safe_str(w.registrar) if hasattr(w, 'registrar') else None,
            "registrationDate": safe_str(w.creation_date) if hasattr(w, 'creation_date') else None,
            "expirationDate": safe_str(w.expiration_date) if hasattr(w, 'expiration_date') else None,
            "updatedDate": safe_str(w.updated_date) if hasattr(w, 'updated_date') else None,
            "nameServers": safe_list(w.name_servers) if hasattr(w, 'name_servers') and w.name_servers else [],
            "status": safe_list(w.status) if hasattr(w, 'status') and w.status else [],
            "registrant": registrant if registrant else None,
            "emails": safe_list(w.emails) if hasattr(w, 'emails') and w.emails else []
        }
        
        return JSONResponse(content={
            "code": 200,
            "msg": "WHOIS 查询成功",
            "data": data
        })
        
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"code": 500, "msg": f"WHOIS 查询失败: {str(e)}", "data": None}
        )


@router.post("/lookup/dns")
def lookup_dns(request: DomainLookupRequest = Body(...)):
    """实时查询 DNS 记录"""
    domain = request.domain.strip()
    
    if not domain:
        return JSONResponse(
            status_code=400,
            content={"code": 400, "msg": "域名不能为空", "data": None}
        )
    
    try:
        records = []
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                for rdata in answers:
                    record = {
                        "type": record_type,
                        "name": domain,
                        "ttl": answers.rrset.ttl,
                        "priority": None
                    }
                    
                    if record_type == "MX":
                        record["value"] = str(rdata.exchange).rstrip('.')
                        record["priority"] = rdata.preference
                    elif record_type == "SOA":
                        record["value"] = f"{rdata.mname} {rdata.rname}"
                    else:
                        record["value"] = str(rdata).rstrip('.')
                    
                    records.append(record)
                    
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                continue
            except Exception:
                continue
        
        if not records:
            return JSONResponse(
                status_code=404,
                content={"code": 404, "msg": "未找到 DNS 记录", "data": None}
            )
        
        return JSONResponse(content={
            "code": 200,
            "msg": "DNS 查询成功",
            "data": {
                "domain": domain,
                "records": records
            }
        })
        
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"code": 500, "msg": f"DNS 查询失败: {str(e)}", "data": None}
        )


@router.post("/lookup/ssl")
def lookup_ssl(request: DomainLookupRequest = Body(...)):
    """实时查询 SSL 证书信息"""
    domain = request.domain.strip()
    
    if not domain:
        return JSONResponse(
            status_code=400,
            content={"code": 400, "msg": "域名不能为空", "data": None}
        )
    
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
                # 解析 issuer 和 subject
                issuer = {}
                for item in cert.get('issuer', []):
                    for key, value in item:
                        issuer[key] = value
                
                subject = {}
                for item in cert.get('subject', []):
                    for key, value in item:
                        subject[key] = value
                
                # 提取 SAN 名称
                san_names = []
                for item in cert.get('subjectAltName', []):
                    if item[0] == 'DNS':
                        san_names.append(item[1])
                
                data = {
                    "domain": domain,
                    "issuer": issuer,
                    "subject": subject,
                    "validity": {
                        "notBefore": cert.get('notBefore'),
                        "notAfter": cert.get('notAfter')
                    },
                    "version": cert.get('version'),
                    "serialNumber": cert.get('serialNumber'),
                    "sanNames": san_names if san_names else None,
                    "isExpired": False,  # 可以根据日期判断
                    "isSelfSigned": issuer == subject
                }
                
                return JSONResponse(content={
                    "code": 200,
                    "msg": "SSL 证书查询成功",
                    "data": data
                })
                
    except socket.timeout:
        return JSONResponse(
            status_code=500,
            content={"code": 500, "msg": "连接超时，请检查域名是否支持 HTTPS", "data": None}
        )
    except socket.gaierror:
        return JSONResponse(
            status_code=404,
            content={"code": 404, "msg": "域名解析失败", "data": None}
        )
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"code": 500, "msg": f"SSL 证书查询失败: {str(e)}", "data": None}
        )


@router.post("/lookup/all")
def lookup_all(request: DomainLookupRequest = Body(...)):
    """
    综合查询域名的所有信息（WHOIS + DNS + SSL）
    如果 save=True，则将查询结果保存到数据库
    """
    domain = request.domain.strip()
    save_to_db = request.save
    
    if not domain:
        return JSONResponse(
            status_code=400,
            content={"code": 400, "msg": "域名不能为空", "data": None}
        )
    
    results = {
        "domain": domain,
        "whois": None,
        "dns": None,
        "certificate": None,
        "errors": [],
        "queryTime": datetime.now().isoformat()
    }
    
    # 查询 WHOIS
    try:
        whois_req = DomainLookupRequest(domain=domain, save=False)
        whois_result = lookup_whois(whois_req)
        whois_data = json.loads(whois_result.body)
        if whois_data.get("code") == 200:
            results["whois"] = whois_data["data"]
    except Exception as e:
        results["errors"].append(f"WHOIS 查询失败: {str(e)}")
    
    # 查询 DNS
    try:
        dns_req = DomainLookupRequest(domain=domain, save=False)
        dns_result = lookup_dns(dns_req)
        dns_data = json.loads(dns_result.body)
        if dns_data.get("code") == 200:
            results["dns"] = dns_data["data"]
    except Exception as e:
        results["errors"].append(f"DNS 查询失败: {str(e)}")
    
    # 查询 SSL
    try:
        ssl_req = DomainLookupRequest(domain=domain, save=False)
        ssl_result = lookup_ssl(ssl_req)
        ssl_data = json.loads(ssl_result.body)
        if ssl_data.get("code") == 200:
            results["certificate"] = ssl_data["data"]
    except Exception as e:
        results["errors"].append(f"SSL 证书查询失败: {str(e)}")
    
    # 如果需要保存到数据库
    if save_to_db and any([results["whois"], results["dns"], results["certificate"]]):
        try:
            save_to_database(domain, results)
            results["saved"] = True
        except Exception as e:
            results["errors"].append(f"保存到数据库失败: {str(e)}")
            results["saved"] = False
    else:
        results["saved"] = False
    
    # 判断查询是否成功
    if not any([results["whois"], results["dns"], results["certificate"]]):
        return JSONResponse(
            status_code=404,
            content={"code": 404, "msg": "所有查询均失败", "data": results}
        )
    
    return JSONResponse(content={
        "code": 200,
        "msg": "查询完成",
        "data": results
    })


def save_to_database(domain: str, results: Dict[str, Any]):
    """将查询结果保存到数据库"""
    with engine.connect() as conn:
        # 检查域名是否存在
        domain_result = conn.execute(
            text("SELECT id FROM domains WHERE domain_name = :domain"),
            {"domain": domain}
        ).fetchone()
        
        if domain_result:
            domain_id = domain_result[0]
        else:
            # 插入新域名
            result = conn.execute(
                text("INSERT INTO domains (domain_name, created_at) VALUES (:domain, NOW())"),
                {"domain": domain}
            )
            conn.commit()
            domain_id = result.lastrowid
        
        # 保存 WHOIS 信息
        if results.get("whois"):
            whois_data = results["whois"]
            conn.execute(
                text("""
                    INSERT INTO whois_info (
                        domain_id, registrar, registration_date, expiration_date, 
                        updated_date, name_servers, registrant, status, query_time
                    ) VALUES (
                        :domain_id, :registrar, :registration_date, :expiration_date,
                        :updated_date, :name_servers, :registrant, :status, NOW()
                    )
                """),
                {
                    "domain_id": domain_id,
                    "registrar": whois_data.get("registrar"),
                    "registration_date": whois_data.get("registrationDate"),
                    "expiration_date": whois_data.get("expirationDate"),
                    "updated_date": whois_data.get("updatedDate"),
                    "name_servers": json.dumps(whois_data.get("nameServers", [])),
                    "registrant": json.dumps(whois_data.get("registrant")) if whois_data.get("registrant") else None,
                    "status": json.dumps(whois_data.get("status", []))
                }
            )
        
        # 保存 DNS 记录
        if results.get("dns") and results["dns"].get("records"):
            for record in results["dns"]["records"]:
                conn.execute(
                    text("""
                        INSERT INTO dns_records (
                            domain_id, record_type, record_name, record_value, ttl, priority
                        ) VALUES (
                            :domain_id, :record_type, :record_name, :record_value, :ttl, :priority
                        )
                    """),
                    {
                        "domain_id": domain_id,
                        "record_type": record["type"],
                        "record_name": record["name"],
                        "record_value": record["value"],
                        "ttl": record.get("ttl"),
                        "priority": record.get("priority")
                    }
                )
        
        # 保存 SSL 证书信息
        if results.get("certificate"):
            cert_data = results["certificate"]
            conn.execute(
                text("""
                    INSERT INTO ssl_certificates (
                        domain_id, issuer, subject, not_before, not_after,
                        serial_number, san_names, is_expired, is_self_signed, created_at
                    ) VALUES (
                        :domain_id, :issuer, :subject, :not_before, :not_after,
                        :serial_number, :san_names, :is_expired, :is_self_signed, NOW()
                    )
                """),
                {
                    "domain_id": domain_id,
                    "issuer": json.dumps(cert_data.get("issuer")) if cert_data.get("issuer") else None,
                    "subject": json.dumps(cert_data.get("subject")) if cert_data.get("subject") else None,
                    "not_before": cert_data.get("validity", {}).get("notBefore"),
                    "not_after": cert_data.get("validity", {}).get("notAfter"),
                    "serial_number": cert_data.get("serialNumber"),
                    "san_names": json.dumps(cert_data.get("sanNames")) if cert_data.get("sanNames") else None,
                    "is_expired": cert_data.get("isExpired", False),
                    "is_self_signed": cert_data.get("isSelfSigned", False)
                }
            )
        
        conn.commit()
