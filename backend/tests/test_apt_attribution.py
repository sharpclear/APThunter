import asyncio
import csv
import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from fastapi import HTTPException
from starlette.requests import Request

from app.api.domain_attribution import (
    DomainAttributionRequest,
    attribute_domain_request,
)
from app.models.apt_attribution.engine import DomainAttributionEngine
from app.models.apt_attribution.infrastructure import (
    CertificateRecord,
    DnsRecord,
    InfrastructureRecord,
    finalize_infrastructure_record,
    infrastructure_record_to_evidence,
)


NODE_FIELDS = [
    "node_id",
    "node_type",
    "value",
    "source",
    "first_seen",
    "last_seen",
    "confidence",
    "attrs_json",
]
EDGE_FIELDS = [
    "src_id",
    "dst_id",
    "edge_type",
    "source",
    "confidence",
    "observed_at",
    "evidence_json",
]


def _write_graph(
    graph_dir: Path,
    *,
    include_direct_domain: bool = True,
    include_spki: bool = False,
) -> None:
    nodes = [
        {
            "node_id": "domain:history",
            "node_type": "Domain",
            "value": "history.evil.test",
            "source": "test",
            "confidence": "0.95",
            "attrs_json": "{}",
        },
        {
            "node_id": "indicator:1",
            "node_type": "Indicator",
            "value": "[domain-name:value = 'history.evil.test']",
            "source": "test",
            "confidence": "0.95",
            "attrs_json": "{}",
        },
        {
            "node_id": "apt:1",
            "node_type": "IntrusionSet",
            "value": "APT-TEST",
            "source": "test",
            "confidence": "0.95",
            "attrs_json": "{}",
        },
    ]
    if not include_direct_domain:
        nodes[0]["value"] = "historical-host.evil.test"
    if include_spki:
        nodes.append(
            {
                "node_id": "spki:1",
                "node_type": "CertificateSPKI",
                "value": "shared-spki-sha256",
                "source": "test",
                "confidence": "0.95",
                "attrs_json": "{}",
            }
        )

    edges = [
        {
            "src_id": "indicator:1",
            "dst_id": "domain:history",
            "edge_type": "based_on",
            "source": "test",
            "confidence": "0.95",
            "evidence_json": "{}",
        },
        {
            "src_id": "indicator:1",
            "dst_id": "apt:1",
            "edge_type": "indicates",
            "source": "test",
            "confidence": "0.95",
            "evidence_json": "{}",
        },
    ]
    if include_spki:
        edges.append(
            {
                "src_id": "domain:history",
                "dst_id": "spki:1",
                "edge_type": "has_certificate_spki",
                "source": "test",
                "confidence": "0.95",
                "evidence_json": "{}",
            }
        )

    graph_dir.mkdir(parents=True, exist_ok=True)
    with (graph_dir / "graph_nodes.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=NODE_FIELDS)
        writer.writeheader()
        for row in nodes:
            writer.writerow({field: row.get(field, "") for field in NODE_FIELDS})
    with (graph_dir / "graph_edges.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=EDGE_FIELDS)
        writer.writeheader()
        for row in edges:
            writer.writerow({field: row.get(field, "") for field in EDGE_FIELDS})


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class DomainAttributionEngineTests(unittest.TestCase):
    def test_history_only_direct_attribution_never_calls_live_lookup(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            graph_dir = Path(temp_dir)
            _write_graph(graph_dir)
            before = {
                path.name: _sha256(path)
                for path in graph_dir.glob("graph_*.csv")
            }
            engine = DomainAttributionEngine(graph_dir)

            with patch(
                "app.models.apt_attribution.engine.LiveInfrastructureLookup.enrich_domain"
            ) as live_lookup:
                result = engine.attribute(
                    ["HTTPS://History.Evil.Test/path"],
                    realtime_enrichment=False,
                )[0]

            live_lookup.assert_not_called()
            self.assertEqual(result["domain"], "history.evil.test")
            self.assertEqual(result["attribution"], "APT-TEST")
            self.assertEqual(result["attribution_level"], "known_apt")
            self.assertGreaterEqual(result["apt_confidence"], 0.75)
            self.assertGreaterEqual(result["strong_evidence_count"], 1)
            self.assertTrue(result["evidence"])
            self.assertTrue(result["path"])
            self.assertIn("历史IOC直接归因", result["reason"])
            self.assertEqual(result["infrastructure"], None)
            after = {
                path.name: _sha256(path)
                for path in graph_dir.glob("graph_*.csv")
            }
            self.assertEqual(before, after)

    def test_realtime_spki_reuse_supports_attribution_without_graph_mutation(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            graph_dir = Path(temp_dir)
            _write_graph(
                graph_dir,
                include_direct_domain=False,
                include_spki=True,
            )
            before = {
                path.name: _sha256(path)
                for path in graph_dir.glob("graph_*.csv")
            }
            record = InfrastructureRecord(
                domain="candidate.evil.test",
                certificates=[
                    CertificateRecord(
                        fingerprint="leaf-certificate-sha256",
                        spki_sha256="shared-spki-sha256",
                        domains=["candidate.evil.test"],
                    )
                ],
                provider_status={"tls": "success"},
            )
            engine = DomainAttributionEngine(graph_dir)

            with patch(
                "app.models.apt_attribution.engine.LiveInfrastructureLookup.enrich_domain",
                return_value=record,
            ):
                result = engine.attribute(
                    ["candidate.evil.test"],
                    realtime_enrichment=True,
                )[0]

            self.assertEqual(result["attribution"], "APT-TEST")
            self.assertEqual(
                result["attribution_level"],
                "infrastructure_supported",
            )
            self.assertGreaterEqual(
                result["high_quality_infrastructure_evidence_count"],
                1,
            )
            self.assertEqual(
                result["infrastructure"]["certificates"][0]["spki_sha256"],
                "shared-spki-sha256",
            )
            after = {
                path.name: _sha256(path)
                for path in graph_dir.glob("graph_*.csv")
            }
            self.assertEqual(before, after)

    def test_infrastructure_fields_generate_graph_aligned_evidence(self):
        record = finalize_infrastructure_record(
            InfrastructureRecord(
                domain="candidate.example",
                ips=["8.8.8.8"],
                dns_records=[
                    DnsRecord("A", "8.8.8.8", ttl=300),
                    DnsRecord("NS", "NS1.EXAMPLE.NET.", ttl=600),
                ],
                nameservers=["NS1.EXAMPLE.NET."],
                certificates=[
                    CertificateRecord(
                        fingerprint="certificate-sha256",
                        spki_sha256="spki-sha256",
                        serial_number="1234",
                    )
                ],
            )
        )
        evidence = infrastructure_record_to_evidence(record)
        pairs = {(item.object_type, item.relation) for item in evidence}

        self.assertEqual(record.ips, ["8.8.8.8"])
        self.assertEqual(record.nameservers, ["ns1.example.net"])
        self.assertTrue(record.dns_record_set_sha256)
        self.assertTrue(record.ip_set_sha256)
        self.assertTrue(record.nameserver_set_sha256)
        self.assertIn(("IP", "resolves_to"), pairs)
        self.assertIn(("DNSRecordSetHash", "has_dns_record_set"), pairs)
        self.assertIn(("CertificateSPKI", "has_certificate_spki"), pairs)


class DomainAttributionApiTests(unittest.TestCase):
    @staticmethod
    def _request(user_id: str = "") -> Request:
        headers = []
        if user_id:
            headers.append((b"x-user-id", user_id.encode("ascii")))
        return Request(
            {
                "type": "http",
                "method": "POST",
                "path": "/api/domain-attribution",
                "headers": headers,
            }
        )

    def test_api_requires_user_header(self):
        payload = DomainAttributionRequest(domains=["example.test"])
        with self.assertRaises(HTTPException) as context:
            asyncio.run(
                attribute_domain_request(
                    payload,
                    self._request(),
                )
            )
        self.assertEqual(context.exception.status_code, 401)

    def test_api_returns_required_attribution_fields(self):
        fake_result = {
            "domain": "example.test",
            "attribution": "APT-TEST",
            "attribution_level": "known_apt",
            "apt_confidence": 0.86,
            "strong_evidence_count": 1,
            "evidence": [{"evidence_type": "historical_exact_ioc_attribution"}],
            "path": [{"node_type": "Domain", "value": "example.test"}],
            "reason": "历史IOC直接归因",
        }
        with patch(
            "app.api.domain_attribution.run_in_threadpool",
            new_callable=AsyncMock,
            return_value=[fake_result],
        ) as threadpool_mock:
            body = asyncio.run(
                attribute_domain_request(
                    DomainAttributionRequest(
                        domains=[
                            "HTTPS://Example.Test/login",
                            "example.test",
                        ],
                        realtime_enrichment=False,
                    ),
                    self._request("1"),
                )
            )

        self.assertEqual(body["count"], 1)
        self.assertEqual(body["live_providers"], [])
        self.assertEqual(
            set(
                [
                    "domain",
                    "attribution",
                    "attribution_level",
                    "apt_confidence",
                    "strong_evidence_count",
                    "evidence",
                    "path",
                    "reason",
                ]
            )
            - set(body["results"][0]),
            set(),
        )
        threadpool_mock.assert_awaited_once()
        self.assertEqual(
            threadpool_mock.call_args.args[1],
            ["example.test"],
        )


if __name__ == "__main__":
    unittest.main()
