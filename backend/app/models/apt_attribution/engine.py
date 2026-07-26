from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from .common import Candidate, normalize_domain, registered_domain
from .historical_graph import HistoricalGraphProvider, decide_attribution
from .infrastructure import (
    InfrastructureRecord,
    LiveInfrastructureConfig,
    LiveInfrastructureLookup,
    finalize_infrastructure_record,
    infrastructure_record_to_evidence,
)


logger = logging.getLogger(__name__)


class AttributionConfigurationError(RuntimeError):
    pass


def _normalize_domains(domains: Iterable[object]) -> List[str]:
    normalized: List[str] = []
    seen = set()
    for value in domains or []:
        domain = normalize_domain(value)
        if domain and domain not in seen:
            seen.add(domain)
            normalized.append(domain)
    return normalized


def _primary_path(evidence: List[Dict[str, object]]) -> List[Dict[str, object]]:
    for item in evidence:
        attrs = item.get("attrs")
        if isinstance(attrs, dict) and isinstance(attrs.get("historical_path"), list):
            return attrs["historical_path"]
    return []


def _reason_text(result: Dict[str, object]) -> str:
    attribution = str(result.get("attribution") or "unknown")
    level = str(result.get("attribution_level") or "unknown")
    confidence = float(result.get("apt_confidence") or 0.0)
    evidence = result.get("evidence") if isinstance(result.get("evidence"), list) else []
    if attribution == "unknown":
        return "历史图谱中未形成满足归因阈值的组织证据路径"
    first = next(
        (
            item
            for item in evidence
            if isinstance(item, dict)
            and item.get("evidence_type") != "attribution_aggregate"
        ),
        {},
    )
    attrs = first.get("attrs") if isinstance(first, dict) else {}
    seed = attrs.get("seed") if isinstance(attrs, dict) and isinstance(attrs.get("seed"), dict) else {}
    seed_type = str(seed.get("type") or attrs.get("start_node_type") or "历史IOC")
    seed_value = str(seed.get("value") or "")
    level_text = "历史IOC直接归因" if level == "known_apt" else "基础设施复用归因"
    seed_text = f"{seed_type}={seed_value}" if seed_value else seed_type
    return f"{level_text}：通过 {seed_text} 关联到 {attribution}，置信度 {confidence:.4f}"


class DomainAttributionEngine:
    def __init__(
        self,
        graph_dir: Path,
        *,
        live_config: Optional[LiveInfrastructureConfig] = None,
        max_workers: int = 4,
        historical_max_hops: int = 4,
        historical_min_confidence: float = 0.0,
        historical_max_paths: int = 20,
    ) -> None:
        self.graph_dir = Path(graph_dir).expanduser().resolve()
        self.max_workers = max(1, int(max_workers or 1))
        self.live_config = live_config or LiveInfrastructureConfig()
        self.historical = HistoricalGraphProvider(
            self.graph_dir,
            max_hops=historical_max_hops,
            min_confidence=historical_min_confidence,
            max_paths=historical_max_paths,
        )

    def validate(self) -> None:
        try:
            self.historical.load()
        except FileNotFoundError as exc:
            raise AttributionConfigurationError(str(exc)) from exc

    def attribute(
        self,
        domains: Iterable[object],
        *,
        realtime_enrichment: bool = False,
        include_infrastructure: bool = True,
    ) -> List[Dict[str, object]]:
        normalized = _normalize_domains(domains)
        if not normalized:
            return []
        self.validate()
        records: Dict[str, InfrastructureRecord] = {}
        if realtime_enrichment:
            lookup = LiveInfrastructureLookup(self.live_config)
            worker_count = min(self.max_workers, len(normalized))
            with ThreadPoolExecutor(max_workers=worker_count) as executor:
                futures = {
                    executor.submit(lookup.enrich_domain, domain): domain
                    for domain in normalized
                }
                for future in as_completed(futures):
                    domain = futures[future]
                    try:
                        records[domain] = future.result()
                    except Exception as exc:
                        logger.exception("域名实时基础设施补全失败 domain=%s", domain)
                        records[domain] = finalize_infrastructure_record(
                            InfrastructureRecord(
                                domain=domain,
                                collection_errors={"runtime": str(exc)},
                                provider_status={"runtime": f"error:{exc}"},
                            )
                        )
        return [
            self._attribute_one(
                domain,
                records.get(domain),
                realtime_enrichment=realtime_enrichment,
                include_infrastructure=include_infrastructure,
            )
            for domain in normalized
        ]

    def _attribute_one(
        self,
        domain: str,
        record: Optional[InfrastructureRecord],
        *,
        realtime_enrichment: bool,
        include_infrastructure: bool,
    ) -> Dict[str, object]:
        seed_evidence = infrastructure_record_to_evidence(record) if record else []
        candidate = Candidate(
            domain=domain,
            registered_domain=registered_domain(domain),
            model_score=1.0,
        )
        historical = self.historical.enrich(candidate, seed_evidence)
        decision = decide_attribution(historical.evidence)
        evidence = decision.get("evidence")
        evidence_list = evidence if isinstance(evidence, list) else []
        result: Dict[str, object] = {
            "domain": domain,
            **decision,
            "path": _primary_path(evidence_list),
            "reason": "",
            "historical_graph_status": historical.status,
            "historical_graph_detail": historical.detail,
            "realtime_enrichment": realtime_enrichment,
            "provider_status": dict(record.provider_status) if record else {},
            "collection_errors": dict(record.collection_errors) if record else {},
        }
        result["reason"] = _reason_text(result)
        if include_infrastructure:
            result["infrastructure"] = record.to_dict() if record else None
        return result


def attribute_domains(
    domains: Iterable[object],
    *,
    graph_dir: Path,
    realtime_enrichment: bool = False,
    include_infrastructure: bool = True,
    live_config: Optional[LiveInfrastructureConfig] = None,
    max_workers: int = 4,
) -> List[Dict[str, object]]:
    engine = DomainAttributionEngine(
        graph_dir,
        live_config=live_config,
        max_workers=max_workers,
    )
    return engine.attribute(
        domains,
        realtime_enrichment=realtime_enrichment,
        include_infrastructure=include_infrastructure,
    )
