from __future__ import annotations

import threading
from pathlib import Path
from typing import Iterable, List

from app.core import config
from app.models.apt_attribution import (
    AttributionConfigurationError,
    DomainAttributionEngine,
    LiveInfrastructureConfig,
)


class RealtimeAttributionDisabledError(RuntimeError):
    pass


_engine_lock = threading.Lock()
_engine_cache_key = None
_engine_cache: DomainAttributionEngine | None = None


def enabled_live_providers() -> frozenset[str]:
    switches = {
        "dns": config.APT_ATTRIBUTION_DNS_ENABLED,
        "dnsrecords": config.APT_ATTRIBUTION_DNS_RECORDS_ENABLED,
        "rdap": config.APT_ATTRIBUTION_RDAP_ENABLED,
        "tls": config.APT_ATTRIBUTION_TLS_ENABLED,
        "ct": config.APT_ATTRIBUTION_CT_ENABLED,
        "ipintel": config.APT_ATTRIBUTION_IPINTEL_ENABLED,
        "web": config.APT_ATTRIBUTION_WEB_ENABLED,
    }
    return frozenset(name for name, enabled in switches.items() if enabled)


def _graph_signature(graph_dir: Path):
    values = []
    for name in ("graph_nodes.csv", "graph_edges.csv"):
        path = graph_dir / name
        try:
            stat = path.stat()
            values.append((name, stat.st_mtime_ns, stat.st_size))
        except FileNotFoundError:
            values.append((name, None, None))
    return tuple(values)


def _engine_key():
    graph_dir = Path(config.APT_ATTRIBUTION_GRAPH_DIR).expanduser().resolve()
    providers = enabled_live_providers()
    return (
        str(graph_dir),
        _graph_signature(graph_dir),
        tuple(sorted(providers)),
        config.APT_ATTRIBUTION_REQUEST_TIMEOUT_SEC,
        config.APT_ATTRIBUTION_REQUEST_RETRIES,
        config.APT_ATTRIBUTION_MAX_WORKERS,
        config.APT_ATTRIBUTION_CERTIFICATE_LIMIT,
        config.APT_ATTRIBUTION_DNS_TRANSPORT,
        config.APT_ATTRIBUTION_DOH_ENDPOINT,
        config.APT_ATTRIBUTION_CT_RATE_LIMIT_SEC,
        config.APT_ATTRIBUTION_HISTORICAL_MAX_HOPS,
        config.APT_ATTRIBUTION_HISTORICAL_MAX_PATHS,
    )


def get_attribution_engine() -> DomainAttributionEngine:
    global _engine_cache, _engine_cache_key
    key = _engine_key()
    with _engine_lock:
        if _engine_cache is not None and _engine_cache_key == key:
            return _engine_cache
        graph_dir = Path(config.APT_ATTRIBUTION_GRAPH_DIR).expanduser().resolve()
        live_config = LiveInfrastructureConfig(
            providers=enabled_live_providers(),
            timeout=max(0.5, float(config.APT_ATTRIBUTION_REQUEST_TIMEOUT_SEC)),
            retries=max(0, int(config.APT_ATTRIBUTION_REQUEST_RETRIES)),
            certificate_limit=max(
                0,
                int(config.APT_ATTRIBUTION_CERTIFICATE_LIMIT),
            ),
            dns_transport=config.APT_ATTRIBUTION_DNS_TRANSPORT,
            doh_endpoint=config.APT_ATTRIBUTION_DOH_ENDPOINT,
            ct_rate_limit_seconds=max(
                0.0,
                float(config.APT_ATTRIBUTION_CT_RATE_LIMIT_SEC),
            ),
        )
        engine = DomainAttributionEngine(
            graph_dir,
            live_config=live_config,
            max_workers=max(1, int(config.APT_ATTRIBUTION_MAX_WORKERS)),
            historical_max_hops=max(
                1,
                int(config.APT_ATTRIBUTION_HISTORICAL_MAX_HOPS),
            ),
            historical_max_paths=max(
                1,
                int(config.APT_ATTRIBUTION_HISTORICAL_MAX_PATHS),
            ),
        )
        engine.validate()
        _engine_cache = engine
        _engine_cache_key = key
        return engine


def attribute_domains(
    domains: Iterable[object],
    *,
    realtime_enrichment: bool,
    include_infrastructure: bool = True,
) -> List[dict]:
    if realtime_enrichment and not config.APT_ATTRIBUTION_REALTIME_ALLOWED:
        raise RealtimeAttributionDisabledError("系统配置已禁用实时基础设施补全")
    if realtime_enrichment and not enabled_live_providers():
        raise RealtimeAttributionDisabledError("系统未启用任何实时基础设施提供方")
    engine = get_attribution_engine()
    return engine.attribute(
        domains,
        realtime_enrichment=realtime_enrichment,
        include_infrastructure=include_infrastructure,
    )


__all__ = [
    "AttributionConfigurationError",
    "RealtimeAttributionDisabledError",
    "attribute_domains",
    "enabled_live_providers",
    "get_attribution_engine",
]
