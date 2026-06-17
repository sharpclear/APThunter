from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit


_DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_TOKEN_RE = re.compile(r"[a-z]+|\d+")

_KNOWN_MULTI_PART_SUFFIXES = {
    "ac.cn",
    "co.jp",
    "co.kr",
    "co.uk",
    "com.au",
    "com.cn",
    "com.hk",
    "com.sg",
    "edu.cn",
    "gov.cn",
    "gov.uk",
    "net.cn",
    "org.cn",
    "org.uk",
}

_KNOWN_PLATFORM_SUFFIXES = {
    "workers.dev",
    "pages.dev",
    "vercel.app",
    "netlify.app",
    "ngrok.app",
}


@dataclass(frozen=True)
class ParsedDomain:
    domain: str
    sld: str
    suffix: str
    subdomain: str


def normalize_domain(raw: Any) -> str:
    value = str(raw or "").strip().strip("\"'`<>[](){}")
    if not value:
        return ""
    if value.startswith("*."):
        value = value[2:]

    try:
        if "://" in value:
            host = urlsplit(value).hostname
        elif value.startswith("//"):
            host = urlsplit(f"http:{value}").hostname
        elif any(separator in value for separator in ["/", "?", "#"]):
            host = urlsplit(f"http://{value}").hostname
        elif ":" in value:
            host = urlsplit(f"//{value}").hostname
        else:
            host = value
    except ValueError:
        return ""

    if not host:
        return ""

    host = host.strip().strip(".").lower()
    try:
        return host.encode("idna").decode("ascii").lower().strip(".")
    except UnicodeError:
        return ""


def is_normalized_domain_like(domain: str) -> bool:
    if not domain or "." not in domain or len(domain) > 253:
        return False
    try:
        ipaddress.ip_address(domain)
        return False
    except ValueError:
        pass

    labels = domain.split(".")
    if len(labels) < 2:
        return False
    return all(label and _DOMAIN_LABEL_RE.match(label) for label in labels)


def _resolve_suffix(labels: list[str]) -> tuple[str, int]:
    if len(labels) >= 3:
        tail2 = ".".join(labels[-2:])
        if tail2 in _KNOWN_PLATFORM_SUFFIXES or tail2 in _KNOWN_MULTI_PART_SUFFIXES:
            return tail2, 2
    return labels[-1], 1


def parse_domain(raw: Any) -> ParsedDomain:
    domain = normalize_domain(raw)
    if not domain:
        return ParsedDomain(domain="", sld="", suffix="", subdomain="")

    labels = [part for part in domain.split(".") if part]
    if len(labels) == 1:
        return ParsedDomain(domain=domain, sld=labels[0], suffix="", subdomain="")

    suffix, suffix_label_count = _resolve_suffix(labels)
    sld_index = len(labels) - suffix_label_count - 1
    if sld_index < 0:
        return ParsedDomain(domain=domain, sld=labels[0], suffix=".".join(labels[1:]), subdomain="")

    sld = labels[sld_index]
    subdomain = ".".join(labels[:sld_index])
    return ParsedDomain(domain=domain, sld=sld, suffix=suffix, subdomain=subdomain)


def tokenize_sld(value: str) -> list[str]:
    text = str(value or "").lower()
    return [item.group(0) for item in _TOKEN_RE.finditer(text)]
