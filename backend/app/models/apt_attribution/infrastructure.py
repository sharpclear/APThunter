from __future__ import annotations

import datetime as dt
import hashlib
import html
import html.parser
import ipaddress
import json
import logging
import re
import socket
import ssl
import statistics
import threading
import time
from collections import Counter
from dataclasses import asdict, dataclass, field
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple
from urllib.parse import quote, urljoin, urlsplit

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

try:
    import dns.resolver
except Exception:  # pragma: no cover - 依赖缺失时记录 provider 状态。
    dns = None

from .common import (
    Evidence,
    normalize_domain,
    registered_domain,
    safe_float,
    stable_json_hash,
    stable_values_hash,
    utc_now,
)


logger = logging.getLogger(__name__)

SUPPORTED_PROVIDERS = frozenset({"dns", "dnsrecords", "rdap", "tls", "ct", "ipintel", "web"})
DEFAULT_PROVIDERS = SUPPORTED_PROVIDERS
HTTP_MAX_BYTES = 256 * 1024
FAVICON_MAX_BYTES = 64 * 1024
FAVICON_LIMIT = 2


@dataclass(frozen=True)
class LiveInfrastructureConfig:
    providers: frozenset[str] = DEFAULT_PROVIDERS
    timeout: float = 12.0
    retries: int = 1
    certificate_limit: int = 10
    dns_transport: str = "auto"
    doh_endpoint: str = "https://cloudflare-dns.com/dns-query"
    ct_rate_limit_seconds: float = 0.5
    ct_retry_base_seconds: float = 2.0
    http_max_bytes: int = HTTP_MAX_BYTES
    favicon_max_bytes: int = FAVICON_MAX_BYTES
    favicon_limit: int = FAVICON_LIMIT

    def __post_init__(self) -> None:
        unknown = set(self.providers) - set(SUPPORTED_PROVIDERS)
        if unknown:
            raise ValueError(f"不支持的实时基础设施提供方: {', '.join(sorted(unknown))}")
        if self.dns_transport not in {"auto", "doh", "system"}:
            raise ValueError("dns_transport 必须是 auto、doh 或 system")


@dataclass
class AsnRecord:
    number: str
    organization: str = ""
    country: str = ""


@dataclass
class MxRecord:
    exchange: str
    priority: int = 0


@dataclass
class DnsRecord:
    record_type: str
    value: str
    ttl: int = 0
    priority: int = 0


@dataclass
class CertificateRecord:
    fingerprint: str
    issuer: str = ""
    subject: str = ""
    not_before: str = ""
    not_after: str = ""
    serial_number: str = ""
    signature_algorithm: str = ""
    key_size: int = 0
    public_key_type: str = ""
    spki_sha256: str = ""
    is_expired: bool = False
    is_self_signed: bool = False
    observed_at: str = ""
    domains: List[str] = field(default_factory=list)


@dataclass
class TlsConnectionRecord:
    connected_ip: str = ""
    version: str = ""
    cipher_name: str = ""
    cipher_protocol: str = ""
    cipher_bits: int = 0
    alpn_protocol: str = ""


@dataclass
class FaviconRecord:
    url: str
    status_code: int = 0
    content_type: str = ""
    content_length: int = 0
    truncated: bool = False
    sha256: str = ""


@dataclass
class HttpProbeRecord:
    scheme: str
    status_code: int = 0
    final_url: str = ""
    redirect_chain: List[str] = field(default_factory=list)
    content_type: str = ""
    content_length: int = 0
    truncated: bool = False
    collected_at: str = ""
    title: str = ""
    body_summary: str = ""
    html_sha256: str = ""
    body_sha256: str = ""
    dom_sha256: str = ""
    generator: str = ""
    header_values: Dict[str, str] = field(default_factory=dict)
    header_set_sha256: str = ""
    cookie_names: List[str] = field(default_factory=list)
    cookie_name_set_sha256: str = ""
    javascript_urls: List[str] = field(default_factory=list)
    stylesheet_urls: List[str] = field(default_factory=list)
    external_resource_hosts: List[str] = field(default_factory=list)
    resource_urls_sha256: str = ""
    favicon_urls: List[str] = field(default_factory=list)
    favicons: List[FaviconRecord] = field(default_factory=list)
    form_actions: List[str] = field(default_factory=list)
    form_action_hosts: List[str] = field(default_factory=list)
    tracking_ids: List[str] = field(default_factory=list)
    error: str = ""


@dataclass
class InfrastructureRecord:
    domain: str
    registered_domain: str = ""
    ips: List[str] = field(default_factory=list)
    asns: List[AsnRecord] = field(default_factory=list)
    dns_records: List[DnsRecord] = field(default_factory=list)
    nameservers: List[str] = field(default_factory=list)
    mailservers: List[MxRecord] = field(default_factory=list)
    cname_targets: List[str] = field(default_factory=list)
    soa_mnames: List[str] = field(default_factory=list)
    soa_rnames: List[str] = field(default_factory=list)
    registrar: str = ""
    rdap_created: str = ""
    rdap_updated: str = ""
    rdap_expires: str = ""
    rdap_statuses: List[str] = field(default_factory=list)
    registrar_normalized: str = ""
    registrant_identity_sha256: str = ""
    registrant_identity_verified: bool = False
    contact_email_domains: List[str] = field(default_factory=list)
    uses_privacy_proxy: bool = False
    certificates: List[CertificateRecord] = field(default_factory=list)
    tls_connections: List[TlsConnectionRecord] = field(default_factory=list)
    http_probes: List[HttpProbeRecord] = field(default_factory=list)
    dns_record_type_counts: Dict[str, int] = field(default_factory=dict)
    dns_ttl_min: int = 0
    dns_ttl_max: int = 0
    dns_ttl_median: int = 0
    dns_ttl_values: List[int] = field(default_factory=list)
    dns_record_set_sha256: str = ""
    ip_set_sha256: str = ""
    ipv4_prefixes_24: List[str] = field(default_factory=list)
    ipv6_prefixes_48: List[str] = field(default_factory=list)
    nameserver_set_sha256: str = ""
    tls_fingerprint_sha256: str = ""
    registration_to_update_days: int = 0
    registration_to_cert_days: int = 0
    domain_lifetime_days: int = 0
    certificate_validity_days: List[int] = field(default_factory=list)
    snapshot_status: str = ""
    snapshot_hashes: Dict[str, str] = field(default_factory=dict)
    previous_snapshot_hashes: Dict[str, str] = field(default_factory=dict)
    snapshot_changes: Dict[str, str] = field(default_factory=dict)
    collection_errors: Dict[str, str] = field(default_factory=dict)
    provider_status: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


def parse_int(value: object, default: int = 0) -> int:
    try:
        return int(str(value).strip())
    except Exception:
        return default


def merge_unique(values: Iterable[object]) -> List[str]:
    return sorted({str(value).strip() for value in values if str(value or "").strip()})


def normalize_asn(value: object) -> str:
    return str(value or "").upper().replace("AS", "").strip()


def normalize_nameserver(value: object) -> str:
    return str(value or "").strip().lower().rstrip(".")


def normalize_mailserver(value: object) -> str:
    return normalize_nameserver(value)


def normalize_label_value(value: object) -> str:
    return re.sub(r"\s+", " ", str(value or "").strip()).lower()


def normalize_registrar(value: object) -> str:
    text = normalize_label_value(value)
    text = re.sub(r"\b(incorporated|inc|llc|ltd|limited|gmbh|corp|corporation|co)\b\.?", "", text)
    text = re.sub(r"[^a-z0-9]+", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def is_public_routable_ip(value: object) -> bool:
    try:
        return bool(ipaddress.ip_address(str(value)).is_global)
    except ValueError:
        return False


def public_suffix_host(value: object) -> str:
    try:
        return normalize_domain(urlsplit(str(value or "")).hostname or "")
    except Exception:
        return ""


def ip_prefix(value: str) -> Tuple[str, str]:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return "", ""
    if isinstance(ip, ipaddress.IPv4Address):
        return f"{ipaddress.ip_network(f'{ip}/24', strict=False).network_address}/24", ""
    return "", f"{ipaddress.ip_network(f'{ip}/48', strict=False).network_address}/48"


def datetime_from_iso(value: str) -> dt.datetime:
    text = str(value or "").strip()
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    parsed = dt.datetime.fromisoformat(text)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.timezone.utc)


def format_datetime(value: object) -> str:
    if not isinstance(value, dt.datetime):
        return ""
    if value.tzinfo is None:
        value = value.replace(tzinfo=dt.timezone.utc)
    return value.astimezone(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def days_between(start: str, end: str) -> int:
    if not start or not end:
        return 0
    try:
        return max(0, (datetime_from_iso(end) - datetime_from_iso(start)).days)
    except Exception:
        return 0


def date_is_expired(value: str) -> bool:
    try:
        return bool(value and datetime_from_iso(value) < dt.datetime.now(dt.timezone.utc))
    except Exception:
        return False


def dns_record_key(record: DnsRecord) -> Tuple[str, str, int, int]:
    return (
        record.record_type.upper(),
        str(record.value).strip().lower().rstrip("."),
        int(record.ttl or 0),
        int(record.priority or 0),
    )


def dedupe_dns_records(values: Sequence[DnsRecord]) -> List[DnsRecord]:
    rows: Dict[Tuple[str, str, int, int], DnsRecord] = {}
    for item in values:
        record_type = str(item.record_type or "").strip().upper()
        value = str(item.value or "").strip()
        if not record_type or not value:
            continue
        if record_type in {"CNAME", "MX", "NS"}:
            value = value.lower().rstrip(".")
        record = DnsRecord(
            record_type=record_type,
            value=value,
            ttl=max(0, int(item.ttl or 0)),
            priority=max(0, int(item.priority or 0)),
        )
        rows[dns_record_key(record)] = record
    return [rows[key] for key in sorted(rows)]


def dns_records_fingerprint_rows(records: Sequence[DnsRecord]) -> List[Dict[str, object]]:
    return [
        {
            "type": item.record_type.upper(),
            "value": item.value,
            "ttl": int(item.ttl or 0),
            "priority": int(item.priority or 0),
        }
        for item in dedupe_dns_records(records)
    ]


def dedupe_mx_records(values: Sequence[MxRecord]) -> List[MxRecord]:
    rows: Dict[Tuple[str, int], MxRecord] = {}
    for item in values:
        exchange = normalize_mailserver(item.exchange)
        if exchange:
            rows[(exchange, max(0, int(item.priority or 0)))] = MxRecord(
                exchange=exchange,
                priority=max(0, int(item.priority or 0)),
            )
    return [rows[key] for key in sorted(rows)]


def dedupe_asns(values: Sequence[AsnRecord]) -> List[AsnRecord]:
    rows: Dict[str, AsnRecord] = {}
    for item in values:
        number = normalize_asn(item.number)
        if not number:
            continue
        existing = rows.get(number)
        rows[number] = AsnRecord(
            number=number,
            organization=item.organization or (existing.organization if existing else ""),
            country=item.country or (existing.country if existing else ""),
        )
    return [rows[key] for key in sorted(rows)]


def dedupe_certificates(values: Sequence[CertificateRecord]) -> List[CertificateRecord]:
    rows: Dict[str, CertificateRecord] = {}
    for item in values:
        key = str(item.fingerprint or item.spki_sha256 or item.serial_number or "").strip().lower()
        if not key:
            continue
        current = rows.get(key)
        if current is None:
            item.domains = merge_unique(normalize_domain(domain) for domain in item.domains)
            rows[key] = item
            continue
        for name in (
            "fingerprint",
            "issuer",
            "subject",
            "not_before",
            "not_after",
            "serial_number",
            "signature_algorithm",
            "public_key_type",
            "spki_sha256",
            "observed_at",
        ):
            if not getattr(current, name) and getattr(item, name):
                setattr(current, name, getattr(item, name))
        current.key_size = current.key_size or item.key_size
        current.is_expired = current.is_expired or item.is_expired
        current.is_self_signed = current.is_self_signed or item.is_self_signed
        current.domains = merge_unique([*current.domains, *item.domains])
    return [rows[key] for key in sorted(rows)]


def dedupe_tls_connections(values: Sequence[TlsConnectionRecord]) -> List[TlsConnectionRecord]:
    rows: Dict[Tuple[str, str, str, str, int, str], TlsConnectionRecord] = {}
    for item in values:
        key = (
            str(item.connected_ip or "").strip(),
            str(item.version or "").strip(),
            str(item.cipher_name or "").strip(),
            str(item.cipher_protocol or "").strip(),
            int(item.cipher_bits or 0),
            str(item.alpn_protocol or "").strip(),
        )
        if any(key):
            rows[key] = TlsConnectionRecord(*key)
    return [rows[key] for key in sorted(rows)]


def dedupe_http_probes(values: Sequence[HttpProbeRecord]) -> List[HttpProbeRecord]:
    rows: Dict[Tuple[str, str, str], HttpProbeRecord] = {}
    for item in values:
        if not item.scheme:
            continue
        item.cookie_names = merge_unique(item.cookie_names)
        item.javascript_urls = merge_unique(item.javascript_urls)
        item.stylesheet_urls = merge_unique(item.stylesheet_urls)
        item.external_resource_hosts = merge_unique(item.external_resource_hosts)
        item.favicon_urls = merge_unique(item.favicon_urls)
        item.form_actions = merge_unique(item.form_actions)
        item.form_action_hosts = merge_unique(item.form_action_hosts)
        item.tracking_ids = merge_unique(item.tracking_ids)
        rows[(item.scheme, item.final_url, item.html_sha256 or item.error)] = item
    return [rows[key] for key in sorted(rows)]


def certificate_fingerprint_rows(certificates: Sequence[CertificateRecord]) -> List[Dict[str, object]]:
    return [
        {
            "fingerprint": cert.fingerprint,
            "issuer": cert.issuer,
            "subject": cert.subject,
            "not_before": cert.not_before,
            "not_after": cert.not_after,
            "serial_number": cert.serial_number,
            "signature_algorithm": cert.signature_algorithm,
            "key_size": cert.key_size,
            "public_key_type": cert.public_key_type,
            "spki_sha256": cert.spki_sha256,
            "domains": cert.domains,
        }
        for cert in certificates
        if cert.fingerprint or cert.spki_sha256 or cert.serial_number
    ]


def tls_fingerprint_rows(values: Sequence[TlsConnectionRecord]) -> List[Dict[str, object]]:
    return [
        {
            "connected_ip": item.connected_ip,
            "version": item.version,
            "cipher_name": item.cipher_name,
            "cipher_protocol": item.cipher_protocol,
            "cipher_bits": item.cipher_bits,
            "alpn_protocol": item.alpn_protocol,
        }
        for item in dedupe_tls_connections(values)
    ]


def http_probe_fingerprint_rows(values: Sequence[HttpProbeRecord]) -> List[Dict[str, object]]:
    rows: List[Dict[str, object]] = []
    for item in dedupe_http_probes(values):
        rows.append(
            {
                "scheme": item.scheme,
                "status_code": item.status_code,
                "final_url": item.final_url,
                "redirect_chain": item.redirect_chain,
                "content_type": item.content_type,
                "title": item.title,
                "html_sha256": item.html_sha256,
                "body_sha256": item.body_sha256,
                "dom_sha256": item.dom_sha256,
                "generator": item.generator,
                "header_values": item.header_values,
                "header_set_sha256": item.header_set_sha256,
                "cookie_names": item.cookie_names,
                "cookie_name_set_sha256": item.cookie_name_set_sha256,
                "resource_urls_sha256": item.resource_urls_sha256,
                "external_resource_hosts": item.external_resource_hosts,
                "favicon_sha256": [favicon.sha256 for favicon in item.favicons if favicon.sha256],
                "form_action_hosts": item.form_action_hosts,
                "tracking_ids": item.tracking_ids,
            }
        )
    return rows


def snapshot_hashes_for_record(record: InfrastructureRecord) -> Dict[str, str]:
    sections = {
        "whois": {
            "registrar": record.registrar,
            "registrar_normalized": record.registrar_normalized,
            "rdap_created": record.rdap_created,
            "rdap_updated": record.rdap_updated,
            "rdap_expires": record.rdap_expires,
            "rdap_statuses": record.rdap_statuses,
            "registrant_identity_sha256": record.registrant_identity_sha256,
            "registrant_identity_verified": record.registrant_identity_verified,
            "contact_email_domains": record.contact_email_domains,
            "uses_privacy_proxy": record.uses_privacy_proxy,
        },
        "dns": {
            "records": dns_records_fingerprint_rows(record.dns_records),
            "ips": record.ips,
            "nameservers": record.nameservers,
            "mailservers": [asdict(item) for item in record.mailservers],
            "cname_targets": record.cname_targets,
            "soa_mnames": record.soa_mnames,
            "soa_rnames": record.soa_rnames,
        },
        "certificate": {
            "certificates": certificate_fingerprint_rows(record.certificates),
            "tls": tls_fingerprint_rows(record.tls_connections),
        },
        "web": {"http_probes": http_probe_fingerprint_rows(record.http_probes)},
    }
    hashes = {
        section: stable_json_hash(value)
        for section, value in sections.items()
        if any(bool(item) for item in value.values())
    }
    if hashes:
        hashes["unified"] = stable_json_hash(hashes)
    return hashes


def snapshot_changes(current: Mapping[str, str], previous: Mapping[str, str]) -> Dict[str, str]:
    changes: Dict[str, str] = {}
    for key, value in current.items():
        old = str(previous.get(key) or "")
        changes[key] = "new" if not old else ("unchanged" if old == value else "changed")
    for key in previous:
        if key not in current:
            changes[key] = "removed"
    return changes


def finalize_infrastructure_record(
    record: InfrastructureRecord,
    previous_snapshot_hashes: Optional[Mapping[str, str]] = None,
) -> InfrastructureRecord:
    record.domain = normalize_domain(record.domain)
    record.registered_domain = registered_domain(record.domain)
    record.ips = merge_unique(ip for ip in record.ips if is_public_routable_ip(ip))
    record.nameservers = merge_unique(normalize_nameserver(item) for item in record.nameservers)
    record.mailservers = dedupe_mx_records(record.mailservers)
    record.cname_targets = merge_unique(normalize_domain(item) for item in record.cname_targets)
    record.soa_mnames = merge_unique(normalize_nameserver(item) for item in record.soa_mnames)
    record.soa_rnames = merge_unique(normalize_nameserver(item) for item in record.soa_rnames)
    record.rdap_statuses = merge_unique(record.rdap_statuses)
    record.contact_email_domains = merge_unique(normalize_domain(item) for item in record.contact_email_domains)
    record.asns = dedupe_asns(record.asns)
    record.dns_records = dedupe_dns_records(record.dns_records)
    record.certificates = dedupe_certificates(record.certificates)
    record.tls_connections = dedupe_tls_connections(record.tls_connections)
    record.http_probes = dedupe_http_probes(record.http_probes)
    record.registrar_normalized = record.registrar_normalized or normalize_registrar(record.registrar)
    record.uses_privacy_proxy = bool(
        record.uses_privacy_proxy or looks_like_privacy_proxy(record.registrar)
    )

    ttl_values = sorted(item.ttl for item in record.dns_records if item.ttl > 0)
    record.dns_ttl_values = sorted(set(ttl_values))
    record.dns_ttl_min = min(ttl_values) if ttl_values else 0
    record.dns_ttl_max = max(ttl_values) if ttl_values else 0
    record.dns_ttl_median = int(statistics.median(ttl_values)) if ttl_values else 0
    record.dns_record_type_counts = dict(
        sorted(Counter(item.record_type.upper() for item in record.dns_records).items())
    )
    record.dns_record_set_sha256 = (
        stable_json_hash(dns_records_fingerprint_rows(record.dns_records))
        if record.dns_records
        else ""
    )
    record.ip_set_sha256 = stable_values_hash(record.ips)
    record.nameserver_set_sha256 = stable_values_hash(record.nameservers)
    ipv4_prefixes: List[str] = []
    ipv6_prefixes: List[str] = []
    for ip in record.ips:
        ipv4, ipv6 = ip_prefix(ip)
        if ipv4:
            ipv4_prefixes.append(ipv4)
        if ipv6:
            ipv6_prefixes.append(ipv6)
    record.ipv4_prefixes_24 = merge_unique(ipv4_prefixes)
    record.ipv6_prefixes_48 = merge_unique(ipv6_prefixes)
    record.tls_fingerprint_sha256 = (
        stable_json_hash(tls_fingerprint_rows(record.tls_connections))
        if record.tls_connections
        else ""
    )

    record.registration_to_update_days = days_between(record.rdap_created, record.rdap_updated)
    first_cert_date = min(
        (cert.not_before for cert in record.certificates if cert.not_before),
        default="",
    )
    record.registration_to_cert_days = days_between(record.rdap_created, first_cert_date)
    record.domain_lifetime_days = days_between(record.rdap_created, record.rdap_expires)
    record.certificate_validity_days = [
        value
        for cert in record.certificates
        if (value := days_between(cert.not_before, cert.not_after)) > 0
    ]

    errors = {
        provider: status
        for provider, status in record.provider_status.items()
        if str(status).startswith("error:")
    }
    for probe in record.http_probes:
        if probe.error:
            errors[f"web_{probe.scheme}"] = probe.error
    record.collection_errors = {**record.collection_errors, **errors}
    previous = dict(previous_snapshot_hashes or record.previous_snapshot_hashes or {})
    record.previous_snapshot_hashes = previous
    record.snapshot_hashes = snapshot_hashes_for_record(record)
    record.snapshot_changes = snapshot_changes(record.snapshot_hashes, previous)
    if record.snapshot_hashes and record.collection_errors:
        record.snapshot_status = "partial"
    elif record.snapshot_hashes:
        record.snapshot_status = "success"
    else:
        record.snapshot_status = "failed" if record.collection_errors else "partial"
    return record


PRIVACY_PROXY_MARKERS = {
    "privacy",
    "proxy",
    "protect",
    "redacted",
    "withheld",
    "gdpr",
    "whoisguard",
    "domains by proxy",
    "data protected",
    "private registration",
    "privacyguardian",
}
GENERIC_CERTIFICATE_ISSUER_MARKERS = {
    "let's encrypt",
    "digicert",
    "sectigo",
    "comodoca",
    "comodo",
    "globalsign",
    "google trust services",
    "cloudflare",
    "amazon",
    "microsoft",
    "zerossl",
    "ssl.com",
    "rapidssl",
    "geotrust",
    "godaddy",
}
SHARED_NAMESERVER_SUFFIXES = (
    ".ns.cloudflare.com",
    ".domaincontrol.com",
    ".googledomains.com",
    ".registrar-servers.com",
    ".ui-dns.com",
    ".ui-dns.biz",
    ".ui-dns.de",
    ".ui-dns.org",
    ".centralnic.net",
    ".ultahost.com",
    ".o2switch.net",
    ".no-ip.com",
    ".magpiedns.com",
    ".cloudflare.com",
    ".reg.ru",
    ".njalla.no",
    ".njalla.in",
    ".njalla.fo",
    ".systemdns.com",
)
SHARED_DOMAIN_SERVICE_SUFFIXES = (
    ".workers.dev",
    ".hopto.org",
    ".slyip.net",
    ".freeddns.org",
    ".no-ip.org",
    ".duckdns.org",
)
GENERIC_WEB_MARKERS = (
    "domain for sale",
    "this domain is parked",
    "buy this domain",
    "page not found there is nothing here yet",
    "suspected phishing cloudflare",
    "website is for sale",
    "is for sale",
    "coming soon",
    "wordpress",
)


def looks_like_privacy_proxy(value: object) -> bool:
    text = normalize_label_value(value)
    return any(marker in text for marker in PRIVACY_PROXY_MARKERS)


def is_generic_certificate_issuer(value: object) -> bool:
    text = normalize_label_value(value)
    return any(marker in text for marker in GENERIC_CERTIFICATE_ISSUER_MARKERS)


def infrastructure_quality_flags(record: InfrastructureRecord) -> Set[str]:
    flags: Set[str] = set()
    nameservers = [normalize_nameserver(item) for item in record.nameservers]
    if nameservers and all(
        any(item.endswith(suffix) for suffix in SHARED_NAMESERVER_SUFFIXES)
        for item in nameservers
    ):
        flags.add("shared_managed_dns")
    if any(record.domain.endswith(suffix) for suffix in SHARED_DOMAIN_SERVICE_SUFFIXES):
        flags.add("shared_domain_service")
    web_text = " ".join(
        f"{probe.title} {probe.body_summary}".casefold() for probe in record.http_probes
    )
    if any(marker in web_text for marker in GENERIC_WEB_MARKERS):
        flags.add("generic_or_parked_web_content")
    if record.uses_privacy_proxy:
        flags.add("whois_privacy_proxy")
    return flags


def infrastructure_feature_quality_multiplier(node_type: str, flags: Set[str]) -> float:
    multiplier = 1.0
    if "shared_managed_dns" in flags and node_type in {
        "Nameserver",
        "NameserverSetHash",
        "MailServer",
        "DNSRecordSetHash",
        "TTLProfile",
    }:
        multiplier *= 0.35
    if "shared_domain_service" in flags and node_type in {
        "IP",
        "IPSetHash",
        "IPPrefix",
        "DNSRecordSetHash",
        "Nameserver",
        "NameserverSetHash",
        "Certificate",
        "CertificateSerial",
        "CertificateSPKI",
        "TLSFingerprint",
    }:
        multiplier *= 0.25
    if "generic_or_parked_web_content" in flags and node_type in {
        "HTMLHash",
        "DOMHash",
        "FaviconHash",
        "HeaderSetHash",
        "CookieNameSetHash",
        "ResourceSetHash",
        "PageGenerator",
    }:
        multiplier *= 0.25
    return multiplier


def flatten_http_values(record: InfrastructureRecord, attr_name: str) -> List[str]:
    return merge_unique(getattr(probe, attr_name, "") for probe in record.http_probes)


def flatten_http_list_values(record: InfrastructureRecord, attr_name: str) -> List[str]:
    values: List[str] = []
    for probe in record.http_probes:
        values.extend(getattr(probe, attr_name, []) or [])
    return merge_unique(values)


def flatten_favicon_hashes(record: InfrastructureRecord) -> List[str]:
    return merge_unique(
        favicon.sha256
        for probe in record.http_probes
        for favicon in probe.favicons
        if favicon.sha256
    )


def flatten_http_final_hosts(record: InfrastructureRecord) -> List[str]:
    return merge_unique(public_suffix_host(probe.final_url) for probe in record.http_probes)


def flatten_redirect_chain_hashes(record: InfrastructureRecord) -> List[str]:
    return merge_unique(
        stable_json_hash(probe.redirect_chain)
        for probe in record.http_probes
        if len(probe.redirect_chain) > 1
    )


def infrastructure_record_to_evidence(record: InfrastructureRecord) -> List[Evidence]:
    """将实时快照转成临时图谱起始证据，不写入历史图谱。"""
    evidence: List[Evidence] = []
    seen: Set[Tuple[str, str, str]] = set()
    quality_flags = infrastructure_quality_flags(record)

    def add(
        node_type: str,
        value: object,
        relation: str,
        *,
        source: str,
        confidence: float,
        attrs: Optional[Dict[str, object]] = None,
    ) -> None:
        node_value = str(value or "").strip()
        if not node_value:
            return
        key = (node_type, node_value.casefold(), relation)
        if key in seen:
            return
        seen.add(key)
        evidence_attrs = dict(attrs or {})
        explicit_multiplier = safe_float(evidence_attrs.get("feature_prior_multiplier"), 1.0)
        quality_multiplier = (
            infrastructure_feature_quality_multiplier(node_type, quality_flags)
            * explicit_multiplier
        )
        evidence_attrs["feature_prior_multiplier"] = round(quality_multiplier, 4)
        evidence_attrs["quality_flags"] = sorted(quality_flags)
        evidence.append(
            Evidence(
                source=source,
                evidence_type=f"infrastructure_{node_type.lower()}",
                confidence=confidence,
                subject=record.domain,
                object_type=node_type,
                object_value=node_value,
                relation=relation,
                observed_at=utc_now(),
                attrs=evidence_attrs,
            )
        )

    for ip in record.ips:
        add("IP", ip, "resolves_to", source="live_infra_dns", confidence=0.75)
    add("IPSetHash", record.ip_set_sha256, "has_ip_set", source="live_infra_dns", confidence=0.9)
    for prefix in [*record.ipv4_prefixes_24, *record.ipv6_prefixes_48]:
        add("IPPrefix", prefix, "resolves_to_prefix", source="live_infra_dns", confidence=0.75)
    for asn in record.asns:
        add(
            "ASN",
            normalize_asn(asn.number),
            "announced_by",
            source="live_infra_ipintel",
            confidence=0.7,
            attrs={"organization": asn.organization, "country": asn.country},
        )
    for nameserver in record.nameservers:
        add("Nameserver", nameserver, "uses_nameserver", source="live_infra_dnsrecords", confidence=0.8)
    add(
        "NameserverSetHash",
        record.nameserver_set_sha256,
        "has_nameserver_set",
        source="live_infra_dnsrecords",
        confidence=0.9,
    )
    for mx in record.mailservers:
        add(
            "MailServer",
            mx.exchange,
            "uses_mailserver",
            source="live_infra_dnsrecords",
            confidence=0.8,
            attrs={"priority": mx.priority},
        )
    for target in record.cname_targets:
        if target and target != record.domain:
            add("Domain", target, "cname_to", source="live_infra_dnsrecords", confidence=0.8)
    add(
        "DNSRecordSetHash",
        record.dns_record_set_sha256,
        "has_dns_record_set",
        source="live_infra_dnsrecords",
        confidence=0.9,
    )
    if record.dns_ttl_values:
        add(
            "TTLProfile",
            stable_json_hash(
                {
                    "min": record.dns_ttl_min,
                    "max": record.dns_ttl_max,
                    "median": record.dns_ttl_median,
                    "values": record.dns_ttl_values,
                }
            ),
            "has_ttl_profile",
            source="live_infra_dnsrecords",
            confidence=0.75,
        )
    add("Registrar", record.registrar, "registered_by", source="live_infra_rdap", confidence=0.75)
    if (
        record.registrar_normalized
        and record.registrar_normalized.casefold() != record.registrar.casefold()
    ):
        add(
            "Registrar",
            record.registrar_normalized,
            "registered_by_normalized",
            source="live_infra_rdap",
            confidence=0.85,
        )
    if record.registrant_identity_verified:
        add(
            "WhoisIdentityHash",
            record.registrant_identity_sha256,
            "has_whois_identity",
            source="live_infra_rdap",
            confidence=0.9,
            attrs={"uses_privacy_proxy": record.uses_privacy_proxy},
        )
    for email_domain in record.contact_email_domains:
        add(
            "EmailDomain",
            email_domain,
            "uses_contact_email_domain",
            source="live_infra_rdap",
            confidence=0.8,
            attrs={"uses_privacy_proxy": record.uses_privacy_proxy},
        )
    for cert in record.certificates:
        cert_domains = merge_unique(normalize_domain(item) for item in cert.domains)
        cert_multiplier = 0.30 if len(cert_domains) > 10 else 1.0
        cert_attrs = {
            "feature_prior_multiplier": cert_multiplier,
            "certificate_domain_count": len(cert_domains),
        }
        add("Certificate", cert.fingerprint, "has_certificate", source="live_infra_tls", confidence=0.9, attrs=cert_attrs)
        if cert.issuer and not is_generic_certificate_issuer(cert.issuer):
            add("CertificateIssuer", cert.issuer, "cert_issued_by", source="live_infra_tls", confidence=0.8)
        add("CertificateSerial", cert.serial_number, "has_certificate_serial", source="live_infra_tls", confidence=0.9, attrs=cert_attrs)
        add("CertificateSPKI", cert.spki_sha256, "has_certificate_spki", source="live_infra_tls", confidence=0.95, attrs=cert_attrs)
        for cert_domain in cert_domains:
            if cert_domain != record.domain:
                add("Domain", cert_domain, "same_cert_as", source="live_infra_tls", confidence=0.85, attrs=cert_attrs)
    add(
        "TLSFingerprint",
        record.tls_fingerprint_sha256,
        "has_tls_fingerprint",
        source="live_infra_tls",
        confidence=0.8,
    )
    for value in flatten_http_final_hosts(record):
        add("HTTPFinalHost", value, "has_http_final_host", source="live_infra_web", confidence=0.8)
    for value in flatten_redirect_chain_hashes(record):
        add("RedirectChainHash", value, "has_redirect_chain", source="live_infra_web", confidence=0.85)
    for value in flatten_http_values(record, "html_sha256"):
        add("HTMLHash", value, "has_html_hash", source="live_infra_web", confidence=0.9)
    for value in flatten_http_values(record, "dom_sha256"):
        add("DOMHash", value, "has_dom_hash", source="live_infra_web", confidence=0.9)
    for value in flatten_http_values(record, "header_set_sha256"):
        add("HeaderSetHash", value, "has_header_set", source="live_infra_web", confidence=0.85)
    for value in flatten_http_values(record, "cookie_name_set_sha256"):
        add("CookieNameSetHash", value, "has_cookie_set", source="live_infra_web", confidence=0.85)
    for value in flatten_http_values(record, "resource_urls_sha256"):
        add("ResourceSetHash", value, "has_resource_set", source="live_infra_web", confidence=0.85)
    for value in flatten_http_list_values(record, "external_resource_hosts"):
        add("ResourceHost", value, "loads_resource_from", source="live_infra_web", confidence=0.75)
    for value in flatten_favicon_hashes(record):
        add("FaviconHash", value, "has_favicon", source="live_infra_web", confidence=0.9)
    for value in flatten_http_list_values(record, "form_action_hosts"):
        add("FormActionHost", value, "has_form_action", source="live_infra_web", confidence=0.85)
    for value in flatten_http_list_values(record, "tracking_ids"):
        add("TrackingID", value, "uses_tracking_id", source="live_infra_web", confidence=0.9)
    for value in flatten_http_values(record, "generator"):
        add("PageGenerator", value, "has_page_generator", source="live_infra_web", confidence=0.8)
    return evidence


def header_values_from_mapping(headers: Mapping[str, object]) -> Dict[str, str]:
    wanted = {
        "server",
        "x-powered-by",
        "via",
        "x-aspnet-version",
        "x-generator",
        "content-language",
        "content-security-policy",
    }
    values: Dict[str, str] = {}
    for key, value in headers.items():
        normalized_key = str(key or "").strip().lower()
        if normalized_key in wanted:
            text = re.sub(r"\s+", " ", str(value or "").strip())
            if text:
                values[normalized_key] = text
    return values


def header_set_fingerprint(headers: Mapping[str, object]) -> str:
    excluded = {
        "date",
        "expires",
        "last-modified",
        "etag",
        "set-cookie",
        "cf-ray",
        "x-request-id",
        "x-amz-cf-id",
    }
    rows = [
        [
            str(key or "").strip().lower(),
            re.sub(r"\s+", " ", str(value or "").strip()),
        ]
        for key, value in headers.items()
        if str(key or "").strip()
        and str(key or "").strip().lower() not in excluded
        and str(value or "").strip()
    ]
    return stable_json_hash(sorted(rows)) if rows else ""


def html_text_summary(value: str, max_chars: int = 500) -> str:
    text = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", value)
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    text = html.unescape(text)
    return re.sub(r"\s+", " ", text).strip()[:max_chars]


def dom_structure_hash(value: str) -> str:
    tags = re.findall(r"(?is)<\s*/?\s*([a-z0-9:-]+)", value)
    normalized = [tag.lower() for tag in tags[:2000]]
    return stable_json_hash(normalized) if normalized else ""


def extract_tracking_ids(value: str) -> List[str]:
    patterns = [
        r"\bUA-\d{4,10}-\d+\b",
        r"\bG-[A-Z0-9]{6,12}\b",
        r"\bGTM-[A-Z0-9]{4,10}\b",
        r"\bhm\.baidu\.com/hm\.js\?([0-9a-f]{16,64})",
        r"\bfbq\(\s*['\"]init['\"]\s*,\s*['\"]([0-9]{6,30})['\"]",
    ]
    found: List[str] = []
    for pattern in patterns:
        for match in re.finditer(pattern, value, flags=re.IGNORECASE):
            found.append(match.group(1) if match.groups() else match.group(0))
    return merge_unique(found)


class PageFeatureParser(html.parser.HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.in_title = False
        self.title_parts: List[str] = []
        self.generator = ""
        self.javascript_urls: List[str] = []
        self.stylesheet_urls: List[str] = []
        self.favicon_urls: List[str] = []
        self.form_actions: List[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        attributes = {key.lower(): str(value or "") for key, value in attrs}
        tag = tag.lower()
        if tag == "title":
            self.in_title = True
        elif tag == "script" and attributes.get("src"):
            self.javascript_urls.append(urljoin(self.base_url, attributes["src"]))
        elif tag == "link":
            rel = attributes.get("rel", "").lower()
            href = attributes.get("href", "")
            if href and "stylesheet" in rel:
                self.stylesheet_urls.append(urljoin(self.base_url, href))
            if href and ("icon" in rel or "shortcut icon" in rel):
                self.favicon_urls.append(urljoin(self.base_url, href))
        elif tag == "meta":
            name = (attributes.get("name") or attributes.get("property") or "").lower()
            if name == "generator" and attributes.get("content"):
                self.generator = attributes["content"].strip()
        elif tag == "form" and attributes.get("action"):
            self.form_actions.append(urljoin(self.base_url, attributes["action"]))

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self.in_title = False

    def handle_data(self, data: str) -> None:
        if self.in_title and data:
            self.title_parts.append(data)

    @property
    def title(self) -> str:
        return re.sub(r"\s+", " ", " ".join(self.title_parts)).strip()


def iter_rdap_entities(data: Mapping[str, object]):
    for item in data.get("entities") or []:
        if not isinstance(item, dict):
            continue
        yield item
        yield from iter_rdap_entities(item)


def extract_vcard_values(entity: Mapping[str, object]) -> Dict[str, List[str]]:
    values: Dict[str, List[str]] = {}
    vcard = entity.get("vcardArray")
    if not isinstance(vcard, list) or len(vcard) < 2 or not isinstance(vcard[1], list):
        return values
    for row in vcard[1]:
        if not isinstance(row, list) or len(row) < 4:
            continue
        key = str(row[0] or "").strip().lower()
        raw = row[3]
        flattened = (
            " ".join(str(part) for part in raw if str(part).strip())
            if isinstance(raw, list)
            else str(raw or "")
        )
        flattened = re.sub(r"\s+", " ", flattened).strip()
        if key and flattened:
            values.setdefault(key, []).append(flattened)
    return values


def email_domain(value: object) -> str:
    text = str(value or "").strip().lower()
    return normalize_domain(text.rsplit("@", 1)[-1]) if "@" in text else ""


def extract_rdap_entity_features(
    data: Mapping[str, object],
) -> Tuple[str, List[str], bool, bool]:
    identity_parts: List[str] = []
    email_domains: List[str] = []
    registrant_found = False
    privacy = looks_like_privacy_proxy(data.get("handle", ""))
    for entity in iter_rdap_entities(data):
        roles = [normalize_label_value(role) for role in entity.get("roles") or []]
        vcard_values = extract_vcard_values(entity)
        privacy = privacy or looks_like_privacy_proxy(" ".join(roles)) or any(
            looks_like_privacy_proxy(value)
            for value_list in vcard_values.values()
            for value in value_list
        )
        is_registrant = "registrant" in roles
        is_contact = is_registrant or bool(
            set(roles) & {"administrative", "technical", "billing"}
        )
        if is_registrant:
            registrant_found = True
            for key in ("fn", "org", "adr"):
                for value in vcard_values.get(key, []):
                    normalized = normalize_label_value(value)
                    if normalized:
                        identity_parts.append(f"{key}:{normalized}")
        if is_contact:
            for value in vcard_values.get("email", []):
                domain = email_domain(value)
                if domain:
                    email_domains.append(domain)
                    if is_registrant:
                        identity_parts.append(f"email_domain:{domain}")
    identity_hash = stable_values_hash(identity_parts)
    return (
        identity_hash,
        merge_unique(email_domains),
        privacy,
        registrant_found and bool(identity_hash),
    )


def extract_rdap_registrar(data: Mapping[str, object]) -> str:
    for entity in iter_rdap_entities(data):
        roles = [normalize_label_value(role) for role in entity.get("roles") or []]
        if "registrar" not in roles:
            continue
        values = extract_vcard_values(entity)
        for key in ("fn", "org"):
            if values.get(key):
                return values[key][0]
        handle = str(entity.get("handle") or "").strip()
        if handle:
            return handle
    return ""


def first_event_date(events: Mapping[str, str], *names: str) -> str:
    lowered = {str(key).lower(): str(value) for key, value in events.items() if value}
    for name in names:
        if lowered.get(name.lower()):
            return lowered[name.lower()]
    return ""


def certificate_name_matches_domain(domain: str, certificate_name: str) -> bool:
    normalized_domain = normalize_domain(domain)
    raw = str(certificate_name or "").strip().lower()
    normalized_name = normalize_domain(raw)
    return bool(
        normalized_domain
        and normalized_name
        and (
            normalized_name == normalized_domain
            or (raw.startswith("*.") and normalized_domain.endswith(f".{normalized_name}"))
        )
    )


def certificate_record_from_der(
    der_bytes: bytes,
    query_domain: str,
    *,
    observed_at: str,
) -> CertificateRecord:
    certificate = x509.load_der_x509_certificate(der_bytes)
    fingerprint = certificate.fingerprint(hashes.SHA256()).hex()
    issuer = certificate.issuer.rfc4514_string()
    subject = certificate.subject.rfc4514_string()
    raw_names: List[str] = []
    try:
        san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        raw_names.extend(san.value.get_values_for_type(x509.DNSName))
    except Exception:
        pass
    raw_names.extend(
        attribute.value
        for attribute in certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    )
    raw_names.append(query_domain)
    not_before = getattr(certificate, "not_valid_before_utc", None) or certificate.not_valid_before
    not_after = getattr(certificate, "not_valid_after_utc", None) or certificate.not_valid_after
    signature_algorithm = ""
    try:
        signature_algorithm = str(certificate.signature_hash_algorithm.name)
    except Exception:
        pass
    key_size = 0
    public_key_type = ""
    spki_sha256 = ""
    try:
        public_key = certificate.public_key()
        public_key_type = type(public_key).__name__
        key_size = parse_int(getattr(public_key, "key_size", 0))
        spki = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        spki_sha256 = hashlib.sha256(spki).hexdigest()
    except Exception:
        pass
    not_after_text = format_datetime(not_after)
    return CertificateRecord(
        fingerprint=fingerprint,
        issuer=issuer,
        subject=subject,
        not_before=format_datetime(not_before),
        not_after=not_after_text,
        serial_number=f"{certificate.serial_number:x}",
        signature_algorithm=signature_algorithm,
        key_size=key_size,
        public_key_type=public_key_type,
        spki_sha256=spki_sha256,
        is_expired=date_is_expired(not_after_text),
        is_self_signed=issuer == subject,
        observed_at=observed_at,
        domains=merge_unique(normalize_domain(name) for name in raw_names),
    )


class LiveInfrastructureLookup:
    def __init__(self, config: LiveInfrastructureConfig) -> None:
        self.config = config
        self.providers = set(config.providers)
        self._dns_cache: Dict[Tuple[str, str], Tuple[List[DnsRecord], str]] = {}
        self._dns_cache_lock = threading.Lock()
        self._rdap_cache: Dict[str, Dict[str, object]] = {}
        self._ct_cache: Dict[str, Dict[str, object]] = {}
        self._cache_lock = threading.Lock()
        self._key_locks: Dict[Tuple[str, str], threading.Lock] = {}
        self._ct_rate_lock = threading.Lock()
        self._ct_next_request_at = 0.0

    def enrich_domain(self, domain: str) -> InfrastructureRecord:
        normalized = normalize_domain(domain)
        if not normalized:
            raise ValueError(f"无效域名: {domain}")
        record = InfrastructureRecord(
            domain=normalized,
            registered_domain=registered_domain(normalized),
        )
        if "dns" in self.providers:
            self._enrich_dns(record)
        if "dnsrecords" in self.providers:
            self._enrich_dns_records(record)
        if "rdap" in self.providers:
            if self._should_attempt_rdap(record):
                self._enrich_rdap(record)
            else:
                record.provider_status["rdap"] = "skipped:no_dns"
        if "tls" in self.providers:
            if self._should_attempt_endpoint(record):
                self._enrich_tls(record)
            else:
                record.provider_status["tls"] = "skipped:no_ip"
        if "ipintel" in self.providers:
            self._enrich_ipintel(record)
        if "ct" in self.providers:
            self._enrich_ct(record)
        if "web" in self.providers:
            if self._should_attempt_endpoint(record):
                self._enrich_web(record)
            else:
                record.provider_status["web"] = "skipped:no_ip"
        return finalize_infrastructure_record(record)

    def _key_lock(self, provider: str, key: str) -> threading.Lock:
        cache_key = (provider, key)
        with self._cache_lock:
            return self._key_locks.setdefault(cache_key, threading.Lock())

    def _should_attempt_endpoint(self, record: InfrastructureRecord) -> bool:
        return bool(record.ips) or not ({"dns", "dnsrecords"} & self.providers)

    def _should_attempt_rdap(self, record: InfrastructureRecord) -> bool:
        if not ({"dns", "dnsrecords"} & self.providers):
            return True
        return bool(
            record.ips
            or record.nameservers
            or record.soa_mnames
            or record.soa_rnames
            or record.cname_targets
        )

    def _request(self, method: str, url: str, **kwargs):
        kwargs.setdefault("timeout", self.config.timeout)
        response = None
        for attempt in range(max(0, self.config.retries) + 1):
            try:
                response = requests.request(method, url, **kwargs)
                if response.status_code not in {429, 500, 502, 503, 504}:
                    return response
                if attempt >= self.config.retries:
                    return response
                retry_after = response.headers.get("Retry-After")
                response.close()
                delay = safe_float(retry_after, 0.0) or min(2.0, 0.25 * (2**attempt))
                time.sleep(delay)
            except Exception:
                if attempt >= self.config.retries:
                    raise
                time.sleep(min(2.0, 0.25 * (2**attempt)))
        return response

    def _enrich_dns(self, record: InfrastructureRecord) -> None:
        statuses: Dict[str, str] = {}
        for record_type in ("A", "AAAA"):
            values, statuses[record_type] = self._resolve_dns_detailed(
                record.domain,
                record_type,
            )
            record.ips.extend(
                item.value for item in values if is_public_routable_ip(item.value)
            )
        record.provider_status["dns"] = "hit" if record.ips else (
            next((status for status in statuses.values() if status.startswith("error:")), "no_hit")
        )
        for key, value in statuses.items():
            record.provider_status[f"dns_{key.lower()}"] = value

    def _resolve_dns_detailed(
        self,
        domain: str,
        record_type: str,
    ) -> Tuple[List[DnsRecord], str]:
        key = (domain.lower().rstrip("."), record_type.upper())
        with self._dns_cache_lock:
            cached = self._dns_cache.get(key)
        if cached is not None:
            return list(cached[0]), cached[1]

        records: List[DnsRecord] = []
        status = ""
        if self.config.dns_transport in {"auto", "doh"}:
            records, status = self._query_doh(domain, record_type)
            if status in {"hit", "no_hit"} or self.config.dns_transport == "doh":
                with self._dns_cache_lock:
                    self._dns_cache[key] = (list(records), status)
                return records, status
        records, status = self._query_system_dns(domain, record_type)
        with self._dns_cache_lock:
            self._dns_cache[key] = (list(records), status)
        return records, status

    def _query_doh(self, domain: str, record_type: str) -> Tuple[List[DnsRecord], str]:
        try:
            response = self._request(
                "GET",
                self.config.doh_endpoint,
                params={"name": domain, "type": record_type},
                headers={"accept": "application/dns-json"},
            )
            response.raise_for_status()
            data = response.json()
        except Exception as exc:
            return [], f"error:{exc}"
        if not isinstance(data, dict) or data.get("Status") == 3:
            return [], "no_hit"
        records: List[DnsRecord] = []
        for item in data.get("Answer") or []:
            if not isinstance(item, dict):
                continue
            text = str(item.get("data") or "").strip()
            ttl = max(0, parse_int(item.get("TTL")))
            if not text:
                continue
            record = self._dns_text_to_record(record_type, text, ttl)
            if record:
                records.append(record)
        records = dedupe_dns_records(records)
        return records, "hit" if records else "no_hit"

    def _query_system_dns(
        self,
        domain: str,
        record_type: str,
    ) -> Tuple[List[DnsRecord], str]:
        if dns is None:
            return [], "skipped:dnspython_unavailable"
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = self.config.timeout
            resolver.lifetime = self.config.timeout
            answers = resolver.resolve(domain, record_type, raise_on_no_answer=False)
        except Exception as exc:
            return [], f"error:{exc}"
        ttl = int(getattr(getattr(answers, "rrset", None), "ttl", 0) or 0)
        records: List[DnsRecord] = []
        for answer in list(answers or []):
            if record_type == "MX":
                text = f"{getattr(answer, 'preference', 0)} {getattr(answer, 'exchange', answer)}"
            elif record_type == "NS":
                text = str(getattr(answer, "target", answer))
            elif record_type == "CNAME":
                text = str(getattr(answer, "target", answer))
            elif record_type == "SOA":
                text = (
                    f"{getattr(answer, 'mname', '')} {getattr(answer, 'rname', '')}"
                ).strip() or str(answer)
            elif record_type == "TXT" and getattr(answer, "strings", None):
                text = "".join(
                    part.decode("utf-8", errors="replace")
                    if isinstance(part, bytes)
                    else str(part)
                    for part in answer.strings
                )
            else:
                text = str(answer)
            record = self._dns_text_to_record(record_type, text, ttl)
            if record:
                records.append(record)
        records = dedupe_dns_records(records)
        return records, "hit" if records else "no_hit"

    @staticmethod
    def _dns_text_to_record(
        record_type: str,
        value: str,
        ttl: int,
    ) -> Optional[DnsRecord]:
        record_type = record_type.upper()
        text = str(value or "").strip().strip('"')
        priority = 0
        if record_type == "MX":
            parts = text.split()
            if len(parts) >= 2 and parts[0].isdigit():
                priority = int(parts[0])
                text = parts[1]
            text = normalize_mailserver(text)
        elif record_type == "NS":
            text = normalize_nameserver(text)
        elif record_type == "CNAME":
            text = normalize_domain(text)
        elif record_type == "SOA":
            parts = text.split()
            text = " ".join(
                [
                    normalize_nameserver(parts[0]) if parts else "",
                    normalize_nameserver(parts[1]) if len(parts) > 1 else "",
                    *parts[2:],
                ]
            ).strip()
        if not text:
            return None
        return DnsRecord(
            record_type=record_type,
            value=text,
            ttl=max(0, ttl),
            priority=max(0, priority),
        )

    def _enrich_dns_records(self, record: InfrastructureRecord) -> None:
        statuses: Dict[str, str] = {}
        registered = record.registered_domain
        for record_type in ("A", "AAAA"):
            rows, statuses[record_type] = self._resolve_dns_detailed(
                record.domain,
                record_type,
            )
            record.dns_records.extend(rows)
            record.ips.extend(
                item.value for item in rows if is_public_routable_ip(item.value)
            )
        rows, statuses["NS"] = self._resolve_dns_detailed(registered, "NS")
        record.dns_records.extend(rows)
        record.nameservers.extend(item.value for item in rows)
        rows, statuses["MX"] = self._resolve_dns_detailed(record.domain, "MX")
        if not rows and registered != record.domain:
            rows, statuses["MX_registered"] = self._resolve_dns_detailed(registered, "MX")
        record.dns_records.extend(rows)
        record.mailservers.extend(MxRecord(item.value, item.priority) for item in rows)
        rows, statuses["TXT"] = self._resolve_dns_detailed(record.domain, "TXT")
        record.dns_records.extend(rows)
        rows, statuses["CNAME"] = self._resolve_dns_detailed(record.domain, "CNAME")
        record.dns_records.extend(rows)
        record.cname_targets.extend(item.value for item in rows)
        rows, statuses["SOA"] = self._resolve_dns_detailed(registered, "SOA")
        record.dns_records.extend(rows)
        for item in rows:
            parts = item.value.split()
            if parts:
                record.soa_mnames.append(parts[0])
            if len(parts) > 1:
                record.soa_rnames.append(parts[1])
        hit = any(status == "hit" for status in statuses.values())
        errors = [status for status in statuses.values() if status.startswith("error:")]
        record.provider_status["dnsrecords"] = "hit" if hit else (
            errors[0] if errors else "no_hit"
        )
        for key, value in statuses.items():
            record.provider_status[f"dns_{key.lower()}"] = value

    def _enrich_rdap(self, record: InfrastructureRecord) -> None:
        result = self._query_rdap(record.registered_domain)
        record.provider_status["rdap"] = str(result.get("status") or "no_hit")
        if result.get("status") != "hit":
            return
        record.registrar = str(result.get("registrar") or "")
        record.registrar_normalized = str(result.get("registrar_normalized") or "")
        record.rdap_created = str(result.get("rdap_created") or "")
        record.rdap_updated = str(result.get("rdap_updated") or "")
        record.rdap_expires = str(result.get("rdap_expires") or "")
        record.rdap_statuses.extend(str(item) for item in result.get("rdap_statuses") or [])
        record.nameservers.extend(str(item) for item in result.get("nameservers") or [])
        record.registrant_identity_sha256 = str(
            result.get("registrant_identity_sha256") or ""
        )
        record.registrant_identity_verified = bool(
            result.get("registrant_identity_verified")
        )
        record.contact_email_domains.extend(
            str(item) for item in result.get("contact_email_domains") or []
        )
        record.uses_privacy_proxy = bool(result.get("uses_privacy_proxy"))

    def _query_rdap(self, domain: str) -> Dict[str, object]:
        with self._cache_lock:
            cached = self._rdap_cache.get(domain)
        if cached is not None:
            return dict(cached)
        with self._key_lock("rdap", domain):
            with self._cache_lock:
                cached = self._rdap_cache.get(domain)
            if cached is not None:
                return dict(cached)
            result = self._fetch_rdap(domain)
            with self._cache_lock:
                self._rdap_cache[domain] = dict(result)
            return result

    def _fetch_rdap(self, domain: str) -> Dict[str, object]:
        try:
            response = self._request(
                "GET",
                f"https://rdap.org/domain/{quote(domain)}",
            )
            if response.status_code == 404:
                return {"status": "no_hit"}
            response.raise_for_status()
            data = response.json()
        except Exception as exc:
            return {"status": f"error:{exc}"}
        if not isinstance(data, dict):
            return {"status": "no_hit"}
        events = {
            str(item.get("eventAction") or "").strip(): str(item.get("eventDate") or "").strip()
            for item in data.get("events") or []
            if isinstance(item, dict) and item.get("eventAction") and item.get("eventDate")
        }
        nameservers = merge_unique(
            normalize_nameserver(item.get("ldhName") or item.get("unicodeName") or "")
            for item in data.get("nameservers") or []
            if isinstance(item, dict)
        )
        identity_hash, email_domains, privacy, verified = extract_rdap_entity_features(data)
        registrar = extract_rdap_registrar(data)
        result: Dict[str, object] = {
            "registrar": registrar,
            "registrar_normalized": normalize_registrar(registrar),
            "rdap_created": first_event_date(events, "registration", "registered"),
            "rdap_updated": first_event_date(
                events,
                "last changed",
                "last update of rdap database",
                "changed",
            ),
            "rdap_expires": first_event_date(events, "expiration", "expiry"),
            "rdap_statuses": merge_unique(data.get("status") or []),
            "nameservers": nameservers,
            "registrant_identity_sha256": identity_hash,
            "registrant_identity_verified": verified,
            "contact_email_domains": email_domains,
            "uses_privacy_proxy": privacy or looks_like_privacy_proxy(registrar),
        }
        result["status"] = "hit" if any(result.values()) else "no_hit"
        return result

    def _enrich_tls(self, record: InfrastructureRecord) -> None:
        observed_at = utc_now()
        try:
            if record.ips:
                target_ip = record.ips[0]
            else:
                resolved = {
                    str(item[4][0])
                    for item in socket.getaddrinfo(
                        record.domain,
                        443,
                        proto=socket.IPPROTO_TCP,
                    )
                    if item and item[4]
                }
                if not resolved or not all(
                    is_public_routable_ip(value) for value in resolved
                ):
                    raise ValueError("TLS 目标不是公网可路由地址")
                target_ip = sorted(resolved)[0]
            context = ssl._create_unverified_context()
            try:
                context.set_alpn_protocols(["h2", "http/1.1"])
            except Exception:
                pass
            with socket.create_connection((target_ip, 443), timeout=self.config.timeout) as sock:
                connected_ip = str(sock.getpeername()[0])
                if not is_public_routable_ip(connected_ip):
                    raise ValueError("TLS 目标不是公网可路由 IP")
                with context.wrap_socket(sock, server_hostname=record.domain) as tls_sock:
                    der_bytes = tls_sock.getpeercert(binary_form=True)
                    cipher = tls_sock.cipher() or ("", "", 0)
                    tls_record = TlsConnectionRecord(
                        connected_ip=connected_ip,
                        version=str(tls_sock.version() or ""),
                        cipher_name=str(cipher[0] or ""),
                        cipher_protocol=str(cipher[1] or ""),
                        cipher_bits=parse_int(cipher[2]),
                        alpn_protocol=str(tls_sock.selected_alpn_protocol() or ""),
                    )
            if not der_bytes:
                raise ValueError("服务端未返回证书")
            record.certificates.append(
                certificate_record_from_der(
                    der_bytes,
                    record.domain,
                    observed_at=observed_at,
                )
            )
            record.tls_connections.append(tls_record)
            record.provider_status["tls"] = "hit"
        except Exception as exc:
            record.provider_status["tls"] = f"error:{exc}"

    def _enrich_ct(self, record: InfrastructureRecord) -> None:
        result = self._query_ct(record.domain)
        record.provider_status["ct"] = str(result.get("status") or "no_hit")
        for item in result.get("certificates") or []:
            if not isinstance(item, dict):
                continue
            not_after = str(item.get("not_after") or "")
            issuer = str(item.get("issuer") or "")
            subject = str(item.get("subject") or "")
            record.certificates.append(
                CertificateRecord(
                    fingerprint=str(item.get("fingerprint") or ""),
                    issuer=issuer,
                    subject=subject,
                    not_before=str(item.get("not_before") or ""),
                    not_after=not_after,
                    serial_number=str(item.get("serial_number") or ""),
                    is_expired=date_is_expired(not_after),
                    is_self_signed=bool(issuer and issuer == subject),
                    observed_at=str(item.get("observed_at") or ""),
                    domains=[str(value) for value in item.get("domains") or []],
                )
            )

    def _query_ct(self, domain: str) -> Dict[str, object]:
        with self._cache_lock:
            cached = self._ct_cache.get(domain)
        if cached is not None:
            return dict(cached)
        with self._key_lock("ct", domain):
            with self._cache_lock:
                cached = self._ct_cache.get(domain)
            if cached is not None:
                return dict(cached)
            result = self._fetch_ct(domain)
            with self._cache_lock:
                self._ct_cache[domain] = dict(result)
            return result

    def _wait_for_ct_slot(self) -> None:
        if self.config.ct_rate_limit_seconds <= 0:
            return
        with self._ct_rate_lock:
            wait_seconds = max(0.0, self._ct_next_request_at - time.monotonic())
            if wait_seconds:
                time.sleep(wait_seconds)
            self._ct_next_request_at = (
                time.monotonic() + self.config.ct_rate_limit_seconds
            )

    def _fetch_ct(self, domain: str) -> Dict[str, object]:
        if self.config.certificate_limit <= 0:
            return {"status": "skipped:certificate_limit_0", "certificates": []}
        try:
            self._wait_for_ct_slot()
            response = self._request(
                "GET",
                f"https://crt.sh/?q={quote(domain)}&output=json",
            )
            if response.status_code == 404:
                return {"status": "no_hit", "certificates": []}
            response.raise_for_status()
            data = response.json()
        except Exception as exc:
            return {"status": f"error:{exc}", "certificates": []}
        if not isinstance(data, list):
            return {"status": "no_hit", "certificates": []}
        certificates: List[Dict[str, object]] = []
        for item in data[:50]:
            if not isinstance(item, dict):
                continue
            raw_names = [
                name.strip()
                for name in str(
                    item.get("name_value") or item.get("common_name") or ""
                ).splitlines()
            ]
            if not any(
                certificate_name_matches_domain(domain, raw_name)
                for raw_name in raw_names
            ):
                continue
            certificate_id = str(
                item.get("sha256")
                or item.get("id")
                or item.get("serial_number")
                or ""
            ).strip()
            if not certificate_id:
                continue
            certificates.append(
                {
                    "fingerprint": certificate_id,
                    "issuer": str(item.get("issuer_name") or ""),
                    "subject": str(item.get("common_name") or ""),
                    "not_before": str(item.get("not_before") or ""),
                    "not_after": str(item.get("not_after") or ""),
                    "serial_number": str(item.get("serial_number") or ""),
                    "observed_at": str(item.get("entry_timestamp") or ""),
                    "domains": merge_unique(normalize_domain(name) for name in raw_names),
                }
            )
            if len(certificates) >= self.config.certificate_limit:
                break
        return {
            "status": "hit" if certificates else "no_hit",
            "certificates": certificates,
        }

    def _enrich_ipintel(self, record: InfrastructureRecord) -> None:
        if not record.ips:
            record.provider_status["ipintel"] = "skipped:no_ip"
            return
        hits = 0
        errors: List[str] = []
        for ip in record.ips:
            try:
                response = self._request("GET", f"https://ipwho.is/{quote(ip)}")
                response.raise_for_status()
                data = response.json()
            except Exception as exc:
                errors.append(str(exc))
                continue
            if not isinstance(data, dict) or not data.get("success", True):
                continue
            connection = data.get("connection") or {}
            if not isinstance(connection, dict):
                continue
            asn = normalize_asn(connection.get("asn"))
            if not asn:
                continue
            record.asns.append(
                AsnRecord(
                    asn,
                    str(connection.get("org") or connection.get("isp") or ""),
                    str(data.get("country_code") or data.get("country") or ""),
                )
            )
            hits += 1
        record.provider_status["ipintel"] = "hit" if hits else (
            f"error:{errors[0]}" if errors else "no_hit"
        )

    @staticmethod
    def _host_has_only_public_addresses(host: str) -> bool:
        try:
            rows = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        except Exception:
            return False
        addresses = {str(row[4][0]) for row in rows if row and row[4]}
        return bool(addresses) and all(is_public_routable_ip(ip) for ip in addresses)

    def _safe_http_get(self, url: str, *, max_redirects: int = 5):
        current_url = url
        history = []
        for _ in range(max_redirects + 1):
            parsed = urlsplit(current_url)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                raise ValueError("HTTP 探测目标 URL 无效")
            if not self._host_has_only_public_addresses(parsed.hostname):
                raise ValueError("HTTP 探测目标不是公网可路由地址")
            response = self._request(
                "GET",
                current_url,
                allow_redirects=False,
                stream=True,
                verify=False,
                headers={
                    "User-Agent": "Mozilla/5.0 (compatible; APTHunter-attribution/1.0)"
                },
            )
            response.history = list(history)
            if response.status_code not in {301, 302, 303, 307, 308}:
                return response
            location = response.headers.get("Location")
            if not location:
                return response
            history.append(response)
            response.close()
            current_url = urljoin(current_url, location)
        for response in history:
            response.close()
        raise ValueError("HTTP 跳转次数超过限制")

    @staticmethod
    def _read_limited_content(response, limit: int) -> Tuple[bytes, bool]:
        chunks: List[bytes] = []
        total = 0
        truncated = False
        for chunk in response.iter_content(chunk_size=16384):
            if not chunk:
                continue
            chunks.append(chunk)
            total += len(chunk)
            if total > limit:
                truncated = True
                break
        content = b"".join(chunks)
        if len(content) > limit:
            content = content[:limit]
            truncated = True
        return content, truncated

    @staticmethod
    def _decode_response(response, content: bytes) -> str:
        encoding = str(response.encoding or response.apparent_encoding or "utf-8")
        try:
            return content.decode(encoding, errors="replace")
        except Exception:
            return content.decode("utf-8", errors="replace")

    @staticmethod
    def _redirect_chain(response) -> List[str]:
        values = [
            str(item.url or "").strip()
            for item in response.history or []
            if str(item.url or "").strip()
        ]
        if str(response.url or "").strip():
            values.append(str(response.url).strip())
        ordered: List[str] = []
        for value in values:
            if value not in ordered:
                ordered.append(value)
        return ordered

    def _enrich_web(self, record: InfrastructureRecord) -> None:
        hits = 0
        for scheme in ("https", "http"):
            probe = self._probe_http(record.domain, scheme)
            record.http_probes.append(probe)
            if not probe.error and probe.status_code:
                hits += 1
        record.provider_status["web"] = "hit" if hits else "no_hit"

    def _probe_http(self, domain: str, scheme: str) -> HttpProbeRecord:
        url = f"{scheme}://{domain}/"
        collected_at = utc_now()
        response = None
        try:
            response = self._safe_http_get(url)
            content, truncated = self._read_limited_content(
                response,
                max(1, self.config.http_max_bytes),
            )
            decoded = self._decode_response(response, content)
            final_url = str(response.url or url)
            content_type = str(response.headers.get("Content-Type", ""))
            parser = PageFeatureParser(final_url)
            is_html = "html" in content_type.lower() or "<html" in decoded[:2048].lower()
            if is_html:
                try:
                    parser.feed(decoded)
                except Exception:
                    pass
            resource_urls = merge_unique(
                [*parser.javascript_urls, *parser.stylesheet_urls]
            )
            final_host = public_suffix_host(final_url)
            external_hosts = merge_unique(
                host
                for host in (public_suffix_host(item) for item in resource_urls)
                if host and host != final_host
            )
            favicon_urls = merge_unique(
                [*parser.favicon_urls, urljoin(final_url, "/favicon.ico")]
            )[: max(0, self.config.favicon_limit)]
            favicons = [self._fetch_favicon(item) for item in favicon_urls]
            form_action_hosts = merge_unique(
                public_suffix_host(item) for item in parser.form_actions
            )
            body_summary = html_text_summary(decoded)
            cookie_names = merge_unique(cookie.name for cookie in response.cookies)
            return HttpProbeRecord(
                scheme=scheme,
                status_code=parse_int(response.status_code),
                final_url=final_url,
                redirect_chain=self._redirect_chain(response),
                content_type=content_type,
                content_length=len(content),
                truncated=truncated,
                collected_at=collected_at,
                title=parser.title,
                body_summary=body_summary,
                html_sha256=hashlib.sha256(content).hexdigest()
                if is_html and content
                else "",
                body_sha256=stable_json_hash(body_summary) if body_summary else "",
                dom_sha256=dom_structure_hash(decoded) if is_html else "",
                generator=parser.generator,
                header_values=header_values_from_mapping(response.headers),
                header_set_sha256=header_set_fingerprint(response.headers),
                cookie_names=cookie_names,
                cookie_name_set_sha256=stable_values_hash(cookie_names),
                javascript_urls=parser.javascript_urls,
                stylesheet_urls=parser.stylesheet_urls,
                external_resource_hosts=external_hosts,
                resource_urls_sha256=stable_values_hash(resource_urls),
                favicon_urls=favicon_urls,
                favicons=favicons,
                form_actions=parser.form_actions,
                form_action_hosts=form_action_hosts,
                tracking_ids=extract_tracking_ids(decoded),
            )
        except Exception as exc:
            return HttpProbeRecord(
                scheme=scheme,
                collected_at=collected_at,
                error=str(exc),
            )
        finally:
            if response is not None:
                response.close()

    def _fetch_favicon(self, url: str) -> FaviconRecord:
        response = None
        try:
            response = self._safe_http_get(url)
            content, truncated = self._read_limited_content(
                response,
                max(1, self.config.favicon_max_bytes),
            )
            return FaviconRecord(
                url=str(response.url or url),
                status_code=parse_int(response.status_code),
                content_type=str(response.headers.get("Content-Type", "")),
                content_length=len(content),
                truncated=truncated,
                sha256=hashlib.sha256(content).hexdigest() if content else "",
            )
        except Exception as exc:
            return FaviconRecord(url=url, content_type=f"error:{exc}")
        finally:
            if response is not None:
                response.close()
