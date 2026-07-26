from __future__ import annotations

import ipaddress
import math
import threading
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Sequence, Set, Tuple

from .common import (
    Candidate,
    Evidence,
    ProviderResult,
    normalize_domain,
    parse_json_field,
    read_csv_rows,
    safe_float,
    split_tokens,
)


STRONG_APT_EVIDENCE_TYPES = {
    "direct_domain_to_apt_entity",
    "historical_exact_ioc_attribution",
    "report_contains_domain_and_apt_entity",
    "indicator_indicates_apt_entity_and_domain",
    "indicator_pattern_indicates_apt_entity",
}
MEDIUM_APT_EVIDENCE_TYPES = {
    "apt_report_keyword_contains_domain",
    "historical_indirect_only_to_apt",
    "historical_medium_path_to_apt",
}
INDIRECT_ONLY_APT_EVIDENCE_TYPES = {"historical_indirect_only_to_apt"}
APT_NODE_TYPES = {"IntrusionSet", "ThreatActor"}
IOC_START_NODE_TYPES = {"Domain", "URL"}
FINGERPRINT_NODE_TYPES = {
    "CertificateIssuer",
    "CertificateSerial",
    "CertificateSPKI",
    "CookieNameSetHash",
    "DNSRecordSetHash",
    "DOMHash",
    "EmailDomain",
    "FaviconHash",
    "FormActionHost",
    "HeaderSetHash",
    "HTTPFinalHost",
    "HTMLHash",
    "IPPrefix",
    "IPSetHash",
    "NameserverSetHash",
    "PageGenerator",
    "RedirectChainHash",
    "ResourceHost",
    "ResourceSetHash",
    "TLSFingerprint",
    "TTLProfile",
    "TrackingID",
    "WhoisIdentityHash",
}
INFRASTRUCTURE_FEATURE_PRIORS = {
    "CertificateSPKI": 0.98,
    "WhoisIdentityHash": 0.96,
    "HTMLHash": 0.94,
    "DNSRecordSetHash": 0.92,
    "IPSetHash": 0.90,
    "TrackingID": 0.90,
    "FaviconHash": 0.88,
    "Certificate": 0.86,
    "ResourceSetHash": 0.84,
    "NameserverSetHash": 0.80,
    "DOMHash": 0.78,
    "CertificateSerial": 0.76,
    "IP": 0.74,
    "RedirectChainHash": 0.72,
    "HTTPFinalHost": 0.68,
    "FormActionHost": 0.62,
    "CookieNameSetHash": 0.58,
    "HeaderSetHash": 0.52,
    "MailServer": 0.44,
    "Nameserver": 0.44,
    "IPPrefix": 0.42,
    "ResourceHost": 0.36,
    "TLSFingerprint": 0.32,
    "EmailDomain": 0.28,
    "ASN": 0.24,
    "PageGenerator": 0.20,
    "TTLProfile": 0.18,
    "Registrar": 0.16,
    "CertificateIssuer": 0.12,
}
INFRASTRUCTURE_FEATURE_MAX_DEGREES = {
    "CertificateIssuer": 20,
    "Registrar": 80,
    "PageGenerator": 40,
    "TTLProfile": 80,
    "EmailDomain": 60,
    "ResourceHost": 80,
    "TLSFingerprint": 100,
    "ASN": 120,
    "IPPrefix": 120,
    "Nameserver": 120,
    "MailServer": 120,
}
DEFAULT_INFRASTRUCTURE_FEATURE_MAX_DEGREE = 160
MIN_INFRASTRUCTURE_DISCRIMINATION = 0.08
INFRASTRUCTURE_START_NODE_TYPES = {
    "IP",
    "ASN",
    "Certificate",
    "Domain",
    "URL",
    "Registrar",
    "Nameserver",
    "MailServer",
} | FINGERPRINT_NODE_TYPES
SHARED_INFRASTRUCTURE_EDGE_TYPES = {
    "resolves_to",
    "same_ip_as",
    "uses_nameserver",
    "same_ns_as",
    "uses_mailserver",
    "same_mx_as",
    "cname_to",
    "same_cname_as",
    "has_certificate",
    "same_cert_as",
    "registered_by",
    "announced_by",
    "cert_issued_by",
    "has_certificate_serial",
    "has_certificate_spki",
    "has_cookie_set",
    "has_dns_record_set",
    "has_dom_hash",
    "has_favicon",
    "has_form_action",
    "has_header_set",
    "has_html_hash",
    "has_http_final_host",
    "has_ip_set",
    "has_nameserver_set",
    "has_page_generator",
    "has_redirect_chain",
    "has_resource_set",
    "has_tls_fingerprint",
    "has_ttl_profile",
    "has_whois_identity",
    "loads_resource_from",
    "registered_by_normalized",
    "resolves_to_prefix",
    "uses_contact_email_domain",
    "uses_tracking_id",
}


@dataclass(frozen=True)
class HistoricalEdge:
    src_id: str
    dst_id: str
    edge_type: str
    source: str
    confidence: float
    observed_at: str = ""
    evidence: Dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class HistoricalStep:
    edge: HistoricalEdge
    forward: bool


def historical_step_edge(step: object) -> HistoricalEdge:
    if isinstance(step, HistoricalStep):
        return step.edge
    if isinstance(step, HistoricalEdge):
        return step
    raise TypeError(f"不支持的历史路径步骤类型: {type(step)!r}")


def historical_step_forward(step: object) -> bool:
    return step.forward if isinstance(step, HistoricalStep) else True


def classify_historical_path(
    edge_path: Sequence[object],
    node_types: Sequence[str],
) -> Optional[str]:
    edge_types = [historical_step_edge(step).edge_type for step in edge_path]
    directions = [historical_step_forward(step) for step in edge_path]
    if not edge_types or not node_types or node_types[0] not in INFRASTRUCTURE_START_NODE_TYPES:
        return None
    if node_types[-1] not in APT_NODE_TYPES or node_types.count("Report") > 1:
        return None
    if (
        len(edge_types) == 1
        and node_types[0] in IOC_START_NODE_TYPES
        and edge_types[0] == "attributed_to"
    ):
        return "historical_exact_ioc_attribution"
    if (
        len(edge_types) == 2
        and node_types[0] in IOC_START_NODE_TYPES
        and node_types[1] == "Indicator"
        and edge_types == ["based_on", "indicates"]
        and directions == [False, True]
    ):
        return "indicator_indicates_apt_entity_and_domain"
    if (
        len(edge_types) == 2
        and node_types[0] in IOC_START_NODE_TYPES
        and node_types[1] == "Report"
        and edge_types == ["contains", "contains"]
        and directions == [False, True]
    ):
        return "report_contains_domain_and_apt_entity"
    if (
        len(edge_types) == 2
        and node_types[0] in INFRASTRUCTURE_START_NODE_TYPES
        and node_types[1] == "Indicator"
        and edge_types == ["based_on", "indicates"]
        and directions == [False, True]
    ):
        return "historical_shared_infrastructure_to_apt"
    if (
        len(edge_types) == 2
        and node_types[0] in INFRASTRUCTURE_START_NODE_TYPES
        and node_types[1] == "Report"
        and edge_types == ["contains", "contains"]
        and directions == [False, True]
    ):
        return "historical_shared_infrastructure_to_apt"
    medium_patterns = [
        (
            {"Report"},
            {"Malware", "Tool"},
            ["contains", "contains", "uses"],
            [False, True, False],
        ),
        (
            {"Report"},
            {"Campaign"},
            ["contains", "contains", "attributed_to"],
            [False, True, True],
        ),
        (
            {"Indicator"},
            {"Campaign"},
            ["based_on", "indicates", "attributed_to"],
            [False, True, True],
        ),
    ]
    if len(edge_types) == 3 and node_types[0] in IOC_START_NODE_TYPES:
        for middle1, middle2, expected_edges, expected_directions in medium_patterns:
            if (
                node_types[1] in middle1
                and node_types[2] in middle2
                and edge_types == expected_edges
                and directions == expected_directions
            ):
                return "historical_medium_path_to_apt"
    if (
        len(edge_types) == 3
        and node_types[0] in IOC_START_NODE_TYPES
        and node_types[1] == "Report"
        and node_types[2] == "AttackPattern"
        and edge_types == ["contains", "contains", "uses"]
        and directions == [False, True, False]
    ):
        return "historical_shared_infrastructure_to_apt"
    if set(edge_types) & SHARED_INFRASTRUCTURE_EDGE_TYPES:
        return "historical_shared_infrastructure_to_apt"
    return None


def infrastructure_rarity_factor(support_count: int) -> float:
    support = max(1, int(support_count or 1))
    return 1.0 / (1.0 + 0.45 * math.log2(support))


def historical_path_confidence(
    evidence_type: str,
    edge_path: Sequence[object],
    *,
    indirect_start: bool = False,
    feature_prior: float = 0.0,
    rarity_factor: float = 1.0,
    ambiguity_factor: float = 1.0,
    observation_confidence: float = 0.5,
    direct_start_available: bool = False,
) -> float:
    if not edge_path:
        return 0.0
    base = {
        "indicator_indicates_apt_entity_and_domain": 0.86,
        "report_contains_domain_and_apt_entity": 0.82,
        "historical_exact_ioc_attribution": 0.78,
        "historical_indirect_only_to_apt": 0.62,
        "historical_medium_path_to_apt": 0.62,
        "historical_shared_infrastructure_to_apt": 0.45,
    }.get(evidence_type, 0.5)
    edge_confidences = [historical_step_edge(step).confidence for step in edge_path]
    if not indirect_start:
        return round(min(base, min(edge_confidences, default=base)), 4)
    prior = max(0.0, min(1.0, feature_prior or 0.30))
    rarity = max(0.0, min(1.0, rarity_factor))
    ambiguity = max(0.0, min(1.0, ambiguity_factor))
    observation = max(0.0, min(1.0, observation_confidence))
    discrimination = prior * rarity * ambiguity * (0.85 + 0.15 * observation)
    average_edge = (
        sum(edge_confidences) / len(edge_confidences) if edge_confidences else 0.5
    )
    edge_factor = 0.85 + 0.15 * max(0.0, min(1.0, average_edge))
    length_factor = max(0.82, 1.0 - 0.04 * max(0, len(edge_path) - 2))
    confidence = (0.30 + 0.62 * discrimination) * edge_factor * length_factor
    if evidence_type == "historical_shared_infrastructure_to_apt" and direct_start_available:
        confidence *= 0.82
    return round(max(0.0, min(0.93, confidence)), 4)


class HistoricalGraphProvider:
    """只读历史图谱匹配器。候选域名和实时证据不会写回 CSV。"""

    def __init__(
        self,
        graph_dir: Path,
        *,
        max_hops: int = 4,
        min_confidence: float = 0.0,
        max_paths: int = 20,
    ) -> None:
        self.graph_dir = Path(graph_dir)
        self.max_hops = max_hops
        self.min_confidence = min_confidence
        self.max_paths = max_paths
        self.nodes: Dict[str, Dict[str, object]] = {}
        self.adjacency: Dict[str, List[Tuple[str, HistoricalEdge, bool]]] = {}
        self.node_ids_by_key: Dict[Tuple[str, str], Set[str]] = {}
        self.url_node_ids_by_host: Dict[str, Set[str]] = {}
        self.node_degrees: Dict[str, int] = {}
        self.node_domain_support: Dict[str, int] = {}
        self.loaded = False
        self._load_lock = threading.Lock()

    @property
    def nodes_path(self) -> Path:
        return self.graph_dir / "graph_nodes.csv"

    @property
    def edges_path(self) -> Path:
        return self.graph_dir / "graph_edges.csv"

    def load(self) -> None:
        if self.loaded:
            return
        with self._load_lock:
            if self.loaded:
                return
            if not self.nodes_path.is_file() or not self.edges_path.is_file():
                raise FileNotFoundError(
                    f"历史图谱目录缺少 graph_nodes.csv 或 graph_edges.csv: {self.graph_dir}"
                )
            for row in read_csv_rows(self.nodes_path):
                node_id = str(row.get("node_id") or "")
                if not node_id:
                    continue
                node = {
                    "node_id": node_id,
                    "node_type": str(row.get("node_type") or ""),
                    "value": str(row.get("value") or ""),
                    "source": str(row.get("source") or ""),
                    "first_seen": str(row.get("first_seen") or ""),
                    "last_seen": str(row.get("last_seen") or ""),
                    "confidence": safe_float(row.get("confidence"), 0.0),
                    "attrs": parse_json_field(row.get("attrs_json"), {}),
                }
                self.nodes[node_id] = node
                self.node_ids_by_key.setdefault(
                    (str(node["node_type"]), str(node["value"]).lower()),
                    set(),
                ).add(node_id)
                if node["node_type"] == "URL":
                    host = normalize_domain(node["value"])
                    if host:
                        self.url_node_ids_by_host.setdefault(host, set()).add(node_id)
            for row in read_csv_rows(self.edges_path):
                confidence = safe_float(row.get("confidence"), 0.0)
                if confidence < self.min_confidence:
                    continue
                edge = HistoricalEdge(
                    src_id=str(row.get("src_id") or ""),
                    dst_id=str(row.get("dst_id") or ""),
                    edge_type=str(row.get("edge_type") or ""),
                    source=str(row.get("source") or ""),
                    confidence=confidence,
                    observed_at=str(row.get("observed_at") or ""),
                    evidence=parse_json_field(row.get("evidence_json"), {}),
                )
                if edge.src_id not in self.nodes or edge.dst_id not in self.nodes:
                    continue
                self.adjacency.setdefault(edge.src_id, []).append(
                    (edge.dst_id, edge, True)
                )
                self.adjacency.setdefault(edge.dst_id, []).append(
                    (edge.src_id, edge, False)
                )
            for node_id, neighbors in self.adjacency.items():
                unique_neighbors = {neighbor_id for neighbor_id, _, _ in neighbors}
                domain_neighbors = {
                    neighbor_id
                    for neighbor_id in unique_neighbors
                    if self.nodes.get(neighbor_id, {}).get("node_type") == "Domain"
                }
                self.node_degrees[node_id] = len(unique_neighbors)
                self.node_domain_support[node_id] = len(domain_neighbors)
            self.loaded = True

    def enrich(
        self,
        candidate: Candidate,
        seed_evidence: Sequence[Evidence] = (),
    ) -> ProviderResult:
        self.load()
        starts = self._candidate_start_nodes(candidate, seed_evidence)
        if not starts:
            return ProviderResult(
                "historical_graph",
                "no_hit",
                detail="no matching historical IOC",
            )
        direct_count = sum(1 for item in starts.values() if item.get("direct"))
        has_direct_start = direct_count > 0
        for item in starts.values():
            item["has_direct_start"] = has_direct_start
        matches = self._find_apt_paths(starts)
        apt_names_by_start: Dict[str, Set[str]] = {}
        for match in matches:
            seed = match.get("seed") if isinstance(match.get("seed"), dict) else {}
            apt = match.get("apt_node") if isinstance(match.get("apt_node"), dict) else {}
            if seed.get("matched_node_id") and apt.get("value"):
                apt_names_by_start.setdefault(
                    str(seed["matched_node_id"]),
                    set(),
                ).add(str(apt["value"]))
        evidence: List[Evidence] = []
        for match in matches:
            seed = match.get("seed") if isinstance(match.get("seed"), dict) else {}
            match["apt_ambiguity_count"] = len(
                apt_names_by_start.get(str(seed.get("matched_node_id") or ""), set())
            ) or 1
            converted = self._path_to_evidence(candidate, match)
            if converted:
                evidence.append(converted)
        evidence.sort(
            key=lambda item: (
                item.confidence,
                bool((item.attrs.get("seed") or {}).get("direct")),
                -int(item.attrs.get("path_length") or 0),
                item.object_value,
            ),
            reverse=True,
        )
        evidence = evidence[: self.max_paths]
        return ProviderResult(
            "historical_graph",
            "hit" if evidence else "no_apt_path",
            evidence,
            detail=(
                f"start_nodes={len(starts)};direct_start_nodes={direct_count};"
                f"infrastructure_start_nodes={len(starts) - direct_count};"
                f"apt_paths={len(evidence)};max_hops={self.max_hops}"
            ),
        )

    def _candidate_start_nodes(
        self,
        candidate: Candidate,
        seed_evidence: Sequence[Evidence],
    ) -> Dict[str, Dict[str, object]]:
        starts: Dict[str, Dict[str, object]] = {}

        def add_start(node_id: str, seed: Dict[str, object]) -> None:
            if not node_id or node_id not in self.nodes:
                return
            scored = self._score_seed_node(node_id, seed)
            if scored is None:
                return
            current = starts.get(node_id)
            if current is None or self._seed_sort_key(scored) > self._seed_sort_key(current):
                starts[node_id] = scored

        for node_id in self.node_ids_by_key.get(
            ("Domain", candidate.domain.lower()),
            set(),
        ):
            add_start(
                node_id,
                {
                    "direct": True,
                    "seed_type": "candidate_domain",
                    "seed_value": candidate.domain,
                    "seed_source": "candidate",
                },
            )
        for node_id in self.url_node_ids_by_host.get(candidate.domain, set()):
            add_start(
                node_id,
                {
                    "direct": True,
                    "seed_type": "candidate_url_host",
                    "seed_value": candidate.domain,
                    "seed_source": "candidate",
                },
            )
        for evidence in seed_evidence:
            for node_type, value in self._seed_keys_from_evidence(evidence):
                seed = {
                    "direct": False,
                    "seed_type": node_type,
                    "seed_value": value,
                    "seed_source": evidence.source,
                    "seed_evidence_type": evidence.evidence_type,
                    "seed_relation": evidence.relation,
                    "seed_subject": evidence.subject,
                    "seed_observation_confidence": evidence.confidence,
                    "seed_feature_prior_multiplier": safe_float(
                        evidence.attrs.get("feature_prior_multiplier"),
                        1.0,
                    ),
                    "seed_quality_flags": evidence.attrs.get("quality_flags") or [],
                }
                for node_id in self.node_ids_by_key.get(
                    (node_type, value.lower()),
                    set(),
                ):
                    add_start(node_id, seed)
                if node_type == "Domain":
                    for node_id in self.url_node_ids_by_host.get(value, set()):
                        add_start(
                            node_id,
                            {
                                **seed,
                                "seed_type": "URLHost",
                            },
                        )
        return starts

    @staticmethod
    def _seed_sort_key(seed: Dict[str, object]) -> Tuple[int, float, float]:
        return (
            1 if seed.get("direct") else 0,
            safe_float(seed.get("seed_discrimination"), 0.0),
            safe_float(seed.get("seed_observation_confidence"), 0.0),
        )

    def _score_seed_node(
        self,
        node_id: str,
        seed: Dict[str, object],
    ) -> Optional[Dict[str, object]]:
        item = dict(seed)
        item["matched_node_id"] = node_id
        degree = self.node_degrees.get(node_id, 0)
        domain_support = self.node_domain_support.get(node_id, 0)
        item["node_degree"] = degree
        item["domain_support"] = domain_support
        if item.get("direct"):
            item.update(
                {
                    "feature_prior": 1.0,
                    "rarity_factor": 1.0,
                    "seed_discrimination": 1.0,
                }
            )
            return item
        node_type = str(
            self.nodes.get(node_id, {}).get("node_type")
            or item.get("seed_type")
            or ""
        )
        relation = str(item.get("seed_relation") or "")
        if node_type in {"Domain", "URL"} or item.get("seed_type") == "URLHost":
            feature_prior = (
                0.76
                if relation in {"same_cert_as", "cname_to", "has_http_final_host"}
                else 0.64
            )
            support = 1
        else:
            feature_prior = INFRASTRUCTURE_FEATURE_PRIORS.get(node_type, 0.30)
            support = domain_support or degree or 1
            max_degree = INFRASTRUCTURE_FEATURE_MAX_DEGREES.get(
                node_type,
                DEFAULT_INFRASTRUCTURE_FEATURE_MAX_DEGREE,
            )
            if degree > max_degree:
                return None
        multiplier = max(
            0.0,
            min(
                1.0,
                safe_float(item.get("seed_feature_prior_multiplier"), 1.0),
            ),
        )
        feature_prior *= multiplier
        rarity = infrastructure_rarity_factor(support)
        observation = safe_float(item.get("seed_observation_confidence"), 0.5)
        discrimination = (
            feature_prior
            * rarity
            * (0.85 + 0.15 * max(0.0, min(1.0, observation)))
        )
        if discrimination < MIN_INFRASTRUCTURE_DISCRIMINATION:
            return None
        item.update(
            {
                "feature_prior": round(feature_prior, 4),
                "rarity_factor": round(rarity, 4),
                "seed_discrimination": round(discrimination, 4),
                "support_count": support,
                "feature_prior_multiplier": round(multiplier, 4),
            }
        )
        return item

    @staticmethod
    def _seed_keys_from_evidence(evidence: Evidence) -> Iterator[Tuple[str, str]]:
        object_type = evidence.object_type
        value = str(evidence.object_value or "").strip()
        if not object_type or not value:
            return
        if object_type == "IP":
            try:
                ipaddress.ip_address(value)
            except ValueError:
                return
            yield "IP", value
            return
        if object_type == "ASN":
            normalized = value.upper().replace("AS", "").strip()
            if normalized:
                yield "ASN", normalized
            return
        if object_type == "Certificate":
            yield "Certificate", value
            return
        if object_type in {"Registrar", "Nameserver", "MailServer"}:
            yield object_type, value
            return
        if object_type in FINGERPRINT_NODE_TYPES:
            yield object_type, value
            return
        if object_type == "Domain":
            domain = normalize_domain(value)
            if domain:
                yield "Domain", domain
            return
        if object_type == "URL":
            yield "URL", value
            host = normalize_domain(value)
            if host:
                yield "Domain", host

    def _find_apt_paths(
        self,
        starts: Dict[str, Dict[str, object]],
    ) -> List[Dict[str, object]]:
        ordered = sorted(
            starts,
            key=lambda node_id: self._seed_sort_key(starts[node_id]),
            reverse=True,
        )
        queue = deque(
            (node_id, [node_id], [], starts[node_id]) for node_id in ordered
        )
        seen: Set[Tuple[str, str, int]] = set()
        matches: List[Dict[str, object]] = []
        match_cap = max(self.max_paths * 10, 100)
        state_cap = max(self.max_paths * 200, 5000)
        searched = 0
        while queue and len(matches) < match_cap and searched < state_cap:
            node_id, node_path, edge_path, seed = queue.popleft()
            searched += 1
            depth = len(edge_path)
            state_key = (
                str(seed.get("matched_node_id") or node_path[0]),
                node_id,
                depth,
            )
            if state_key in seen:
                continue
            seen.add(state_key)
            node = self.nodes.get(node_id, {})
            if depth > 0 and node.get("node_type") in APT_NODE_TYPES:
                node_types = [
                    str(self.nodes.get(value, {}).get("node_type", ""))
                    for value in node_path
                ]
                if classify_historical_path(edge_path, node_types):
                    matches.append(
                        {
                            "node_path": node_path,
                            "edge_path": edge_path,
                            "apt_node": node,
                            "seed": seed,
                        }
                    )
                continue
            if depth >= self.max_hops:
                continue
            for neighbor_id, edge, forward in self.adjacency.get(node_id, []):
                if neighbor_id in node_path:
                    continue
                next_path = [*node_path, neighbor_id]
                if not self._should_expand_path(next_path):
                    continue
                if not seed.get("direct") and not self._should_expand_indirect_path(
                    node_path,
                    neighbor_id,
                ):
                    continue
                queue.append(
                    (
                        neighbor_id,
                        next_path,
                        [*edge_path, HistoricalStep(edge, forward)],
                        seed,
                    )
                )
        unique: Dict[Tuple[str, str, Tuple[str, ...]], Dict[str, object]] = {}
        for match in matches:
            seed = match.get("seed") if isinstance(match.get("seed"), dict) else {}
            apt = match.get("apt_node") if isinstance(match.get("apt_node"), dict) else {}
            edge_path = list(match.get("edge_path") or [])
            key = (
                str(seed.get("matched_node_id") or ""),
                str(apt.get("value") or ""),
                tuple(historical_step_edge(step).edge_type for step in edge_path),
            )
            current = unique.get(key)
            if current is None or len(edge_path) < len(current.get("edge_path") or []):
                unique[key] = match
        return list(unique.values())

    def _should_expand_indirect_path(
        self,
        node_path: Sequence[str],
        neighbor_id: str,
    ) -> bool:
        current_type = str(
            self.nodes.get(node_path[-1], {}).get("node_type", "")
        )
        next_type = str(self.nodes.get(neighbor_id, {}).get("node_type", ""))
        depth = len(node_path) - 1
        if next_type in APT_NODE_TYPES:
            return True
        if depth == 0:
            return next_type in {"Domain", "URL", "IP", "Indicator", "Report"}
        if current_type in {"IP", "URL"}:
            return next_type in {"Domain", "Indicator", "Report"}
        if current_type == "Domain":
            return next_type in {"Indicator", "Report", *APT_NODE_TYPES}
        if current_type in {"Indicator", "Report"}:
            return next_type in APT_NODE_TYPES
        return False

    def _should_expand_path(self, node_path: Sequence[str]) -> bool:
        node_types = [
            str(self.nodes.get(node_id, {}).get("node_type", ""))
            for node_id in node_path
        ]
        if node_types.count("Report") > 1:
            return False
        return not (
            len(node_types) >= 3
            and node_types[-2] == "AttackPattern"
            and node_types[-1] == "Report"
        )

    def _path_to_evidence(
        self,
        candidate: Candidate,
        match: Dict[str, object],
    ) -> Optional[Evidence]:
        apt = match.get("apt_node")
        if not isinstance(apt, dict):
            return None
        edge_path = list(match.get("edge_path") or [])
        node_path = list(match.get("node_path") or [])
        node_types = [
            str(self.nodes.get(node_id, {}).get("node_type", ""))
            for node_id in node_path
        ]
        evidence_type = classify_historical_path(edge_path, node_types)
        if not evidence_type:
            return None
        seed = match.get("seed") if isinstance(match.get("seed"), dict) else {}
        direct_available = bool(
            seed.get("has_direct_start", seed.get("direct", True))
        )
        if seed and not seed.get("direct"):
            if (
                not direct_available
                and evidence_type == "historical_shared_infrastructure_to_apt"
            ):
                evidence_type = "historical_indirect_only_to_apt"
            elif evidence_type in STRONG_APT_EVIDENCE_TYPES | MEDIUM_APT_EVIDENCE_TYPES:
                evidence_type = (
                    "historical_shared_infrastructure_to_apt"
                    if direct_available
                    else "historical_indirect_only_to_apt"
                )
        ambiguity_count = max(1, int(match.get("apt_ambiguity_count") or 1))
        ambiguity_factor = 1.0 / math.sqrt(ambiguity_count)
        confidence = historical_path_confidence(
            evidence_type,
            edge_path,
            indirect_start=not bool(seed.get("direct", True)),
            feature_prior=safe_float(seed.get("feature_prior"), 0.0),
            rarity_factor=safe_float(seed.get("rarity_factor"), 1.0),
            ambiguity_factor=ambiguity_factor,
            observation_confidence=safe_float(
                seed.get("seed_observation_confidence"),
                0.5,
            ),
            direct_start_available=direct_available,
        )
        source_node = (
            self.nodes.get(node_path[-2], {}) if len(node_path) >= 2 else {}
        )
        return Evidence(
            source="historical_graph",
            evidence_type=evidence_type,
            confidence=confidence,
            subject=candidate.domain,
            object_type=str(apt.get("node_type") or "IntrusionSet"),
            object_value=str(apt.get("value") or ""),
            relation="attributed_to",
            observed_at=(
                historical_step_edge(edge_path[-1]).observed_at if edge_path else ""
            ),
            attrs={
                "graph_src_type": source_node.get("node_type", "Domain"),
                "graph_src_value": source_node.get("value", candidate.domain),
                "historical_path": self._format_path(node_path, edge_path),
                "edge_types": [
                    historical_step_edge(step).edge_type for step in edge_path
                ],
                "directions": [
                    "forward" if historical_step_forward(step) else "reverse"
                    for step in edge_path
                ],
                "node_types": node_types,
                "path_length": len(edge_path),
                "start_node_type": node_types[0] if node_types else "",
                "direct_start_available": direct_available,
                "feature_prior": safe_float(seed.get("feature_prior"), 0.0),
                "feature_prior_multiplier": safe_float(
                    seed.get("feature_prior_multiplier"),
                    1.0,
                ),
                "quality_flags": seed.get("seed_quality_flags") or [],
                "rarity_factor": safe_float(seed.get("rarity_factor"), 1.0),
                "apt_ambiguity_count": ambiguity_count,
                "ambiguity_factor": round(ambiguity_factor, 4),
                "seed_discrimination": safe_float(
                    seed.get("seed_discrimination"),
                    0.0,
                ),
                "domain_support": int(seed.get("domain_support") or 0),
                "node_degree": int(seed.get("node_degree") or 0),
                "seed": {
                    "direct": bool(seed.get("direct", True)),
                    "type": seed.get("seed_type", ""),
                    "value": seed.get("seed_value", ""),
                    "source": seed.get("seed_source", ""),
                    "evidence_type": seed.get("seed_evidence_type", ""),
                    "relation": seed.get("seed_relation", ""),
                    "subject": seed.get("seed_subject", ""),
                    "matched_node_id": seed.get("matched_node_id", ""),
                    "observation_confidence": safe_float(
                        seed.get("seed_observation_confidence"),
                        0.0,
                    ),
                    "quality_flags": seed.get("seed_quality_flags") or [],
                },
            },
        )

    def _format_path(
        self,
        node_path: Sequence[str],
        edge_path: Sequence[object],
    ) -> List[Dict[str, object]]:
        formatted: List[Dict[str, object]] = []
        for index, node_id in enumerate(node_path):
            node = self.nodes.get(node_id, {})
            item: Dict[str, object] = {
                "node_id": node_id,
                "node_type": node.get("node_type", ""),
                "value": node.get("value", ""),
            }
            if index < len(edge_path):
                step = edge_path[index]
                edge = historical_step_edge(step)
                item["next_edge"] = {
                    "edge_type": edge.edge_type,
                    "source": edge.source,
                    "confidence": edge.confidence,
                    "observed_at": edge.observed_at,
                    "direction": (
                        "forward"
                        if historical_step_forward(step)
                        else "reverse"
                    ),
                    "src_id": edge.src_id,
                    "dst_id": edge.dst_id,
                }
            formatted.append(item)
        return formatted


def high_quality_infrastructure_evidence_count(
    evidence: Sequence[Evidence],
    apt_name: str,
) -> int:
    signatures: Set[str] = set()
    for item in evidence:
        if (
            not apt_name
            or item.object_value != apt_name
            or item.evidence_type != "historical_indirect_only_to_apt"
            or item.confidence < 0.62
            or int(item.attrs.get("apt_ambiguity_count") or 1) > 2
            or safe_float(item.attrs.get("seed_discrimination"), 0.0) < 0.28
            or safe_float(item.attrs.get("feature_prior"), 0.0) < 0.65
            or safe_float(item.attrs.get("feature_prior_multiplier"), 1.0) < 0.5
        ):
            continue
        seed = item.attrs.get("seed") if isinstance(item.attrs.get("seed"), dict) else {}
        signatures.add(f"{seed.get('type', '')}:{seed.get('value', '')}")
    return len(signatures)


def attribution_evidence_count(
    evidence: Sequence[Evidence],
    apt_name: str,
    evidence_types: Set[str],
) -> int:
    signatures: Set[str] = set()
    for item in evidence:
        if item.object_value != apt_name or item.evidence_type not in evidence_types:
            continue
        seed = item.attrs.get("seed") if isinstance(item.attrs.get("seed"), dict) else {}
        if seed and (seed.get("type") or seed.get("value")):
            signatures.add(f"{seed.get('type', '')}:{seed.get('value', '')}")
        else:
            signatures.add(
                f"{item.source}:{item.evidence_type}:{item.subject}:{item.object_value}"
            )
    return len(signatures)


def compute_attribution(
    evidence: Sequence[Evidence],
) -> Tuple[str, str, float, int, List[Dict[str, object]]]:
    candidates: Dict[str, Dict[str, object]] = {}
    for item in evidence:
        if (
            item.object_type not in {"IntrusionSet", "Campaign", "ThreatActor"}
            or not item.object_value
        ):
            continue
        candidate = candidates.setdefault(
            item.object_value,
            {
                "entity_type": item.object_type,
                "strong_signatures": set(),
                "independent": {},
                "reasons": [],
            },
        )
        raw_types = item.attrs.get("evidence_types") or []
        types = (
            set(split_tokens(raw_types))
            if isinstance(raw_types, str)
            else {str(value) for value in raw_types}
        )
        is_strong = bool(types & STRONG_APT_EVIDENCE_TYPES) or (
            item.evidence_type in STRONG_APT_EVIDENCE_TYPES
        )
        is_medium = bool(types & MEDIUM_APT_EVIDENCE_TYPES) or (
            item.evidence_type in MEDIUM_APT_EVIDENCE_TYPES
        )
        confidence = item.confidence
        if is_strong:
            confidence = max(confidence, 0.75)
        elif is_medium:
            confidence = max(confidence, 0.58)
        seed = item.attrs.get("seed") if isinstance(item.attrs.get("seed"), dict) else {}
        signature = (
            f"seed:{seed.get('type', '')}:{seed.get('value', '')}"
            if seed and (seed.get("type") or seed.get("value"))
            else f"evidence:{item.source}:{item.evidence_type}:{item.subject}"
        )
        independent = candidate["independent"]
        independent[signature] = max(
            safe_float(independent.get(signature), 0.0),
            confidence,
        )
        if is_strong:
            candidate["strong_signatures"].add(signature)
        candidate["reasons"].append(item.to_dict())
    if not candidates:
        return "", "unknown", 0.0, 0, []

    for candidate in candidates.values():
        strengths = sorted(
            (safe_float(value, 0.0) for value in candidate["independent"].values()),
            reverse=True,
        )
        candidate["confidence"] = min(
            0.98,
            strengths[0] + 0.12 * sum(strengths[1:]) if strengths else 0.0,
        )
        candidate["strong"] = len(candidate["strong_signatures"])
        candidate["independent_count"] = len(strengths)
    ranked = sorted(
        candidates.items(),
        key=lambda row: (
            -float(row[1]["confidence"]),
            -int(row[1]["strong"]),
            -int(row[1]["independent_count"]),
            row[0].casefold(),
        ),
    )
    best_name, best = ranked[0]
    raw_confidence = float(best["confidence"])
    runner_up_name = ranked[1][0] if len(ranked) > 1 else ""
    runner_up_confidence = (
        float(ranked[1][1]["confidence"]) if len(ranked) > 1 else 0.0
    )
    margin = raw_confidence - runner_up_confidence
    if runner_up_confidence > 0:
        margin_factor = 0.80 + 0.20 * min(
            1.0,
            max(0.0, margin) / 0.20,
        )
        final_confidence = raw_confidence * margin_factor
    else:
        margin_factor = 1.0
        final_confidence = raw_confidence
    aggregate_reason = {
        "source": "scoring",
        "evidence_type": "attribution_aggregate",
        "confidence": round(final_confidence, 4),
        "subject": "",
        "object_type": str(best["entity_type"]),
        "object_value": best_name,
        "relation": "ranked_above",
        "observed_at": "",
        "attrs": {
            "raw_confidence": round(raw_confidence, 4),
            "independent_evidence_count": int(best["independent_count"]),
            "runner_up": runner_up_name,
            "runner_up_confidence": round(runner_up_confidence, 4),
            "margin": round(margin, 4),
            "margin_factor": round(margin_factor, 4),
        },
    }
    return (
        best_name,
        str(best["entity_type"]),
        round(min(0.98, final_confidence), 4),
        int(best["strong"]),
        [*list(best["reasons"]), aggregate_reason],
    )


def decide_attribution(
    evidence: Sequence[Evidence],
) -> Dict[str, object]:
    apt_name, apt_type, confidence, strong_count, reasons = compute_attribution(evidence)
    aggregate_attrs = next(
        (
            item.get("attrs")
            for item in reversed(reasons)
            if item.get("evidence_type") == "attribution_aggregate"
            and isinstance(item.get("attrs"), dict)
        ),
        {},
    )
    margin = (
        safe_float(aggregate_attrs.get("margin"), 0.0)
        if isinstance(aggregate_attrs, dict)
        else 0.0
    )
    indirect_count = attribution_evidence_count(
        evidence,
        apt_name,
        INDIRECT_ONLY_APT_EVIDENCE_TYPES,
    )
    high_quality_count = high_quality_infrastructure_evidence_count(
        evidence,
        apt_name,
    )
    if apt_name and confidence >= 0.65 and strong_count >= 1:
        attribution = apt_name
        level = "known_apt"
    elif (
        apt_name
        and confidence >= 0.68
        and indirect_count >= 1
        and high_quality_count >= 1
        and margin >= 0.08
    ):
        attribution = apt_name
        level = "infrastructure_supported"
    else:
        attribution = "unknown"
        level = "unknown"
        apt_type = "unknown"
    return {
        "attribution": attribution,
        "attribution_level": level,
        "apt_entity_type": apt_type,
        "apt_confidence": confidence,
        "strong_evidence_count": strong_count,
        "indirect_only_evidence_count": indirect_count,
        "high_quality_infrastructure_evidence_count": high_quality_count,
        "score_margin": round(margin, 4),
        "evidence": reasons,
    }
