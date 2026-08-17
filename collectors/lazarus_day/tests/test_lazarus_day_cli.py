from __future__ import annotations

import hashlib
import json
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

import pytest

from scripts.lazarus_day import cli as cli_module
from scripts.lazarus_day.cli import _write_invocation_manifest, build_parser, run
from scripts.lazarus_day.models import (
    CollectorError,
    CollectorLockError,
    FetchError,
    FetchResult,
)


FIXTURES = Path(__file__).parent / "fixtures" / "lazarus_day"
NOW = datetime(2026, 7, 29, 8, 0, tzinfo=timezone.utc)
RSS_URL = "https://lazarus.day/reports/feed/"
DETAIL_URL = (
    "https://lazarus.day/reports/kimsuky-phishing-fixture-AbC12/"
)
ORIGINAL_URL = "https://asec.example/research/kimsuky-fixture"
UNKNOWN_DETAIL_URL = (
    "https://lazarus.day/reports/unknown-actor-fixture-GhI56/"
)
UNKNOWN_ORIGINAL_URL = "https://research.example/unknown"


class FixtureClient:
    def __init__(self, *, fail_detail: bool = False) -> None:
        self.fail_detail = fail_detail
        self.closed = False

    def get(self, url: str) -> FetchResult:
        if url == RSS_URL:
            body = (FIXTURES / "feed.xml").read_text(encoding="utf-8")
            return _result(url, body, "application/rss+xml")
        if url == DETAIL_URL:
            if self.fail_detail:
                raise FetchError("offline detail failure")
            body = (FIXTURES / "detail_event.html").read_text(encoding="utf-8")
            return _result(url, body, "text/html")
        if url == ORIGINAL_URL:
            body = (FIXTURES / "original.html").read_text(encoding="utf-8")
            return _result(url, body, "text/html")
        raise AssertionError(f"unexpected URL: {url}")

    def close(self) -> None:
        self.closed = True


class UnknownActorClient(FixtureClient):
    def get(self, url: str) -> FetchResult:
        if url == RSS_URL:
            body = """<?xml version="1.0" encoding="utf-8"?>
<rss version="2.0"><channel>
<item>
<title>NewCluster backdoor activity</title>
<link>https://lazarus.day/reports/unknown-actor-fixture-GhI56/</link>
<description>NewCluster delivered a malicious backdoor in an attack. | Source: https://research.example/unknown (Researcher) | Tags: Backdoor</description>
<pubDate>Thu, 23 Jul 2026 00:00:00 +0000</pubDate>
</item>
</channel></rss>"""
            return _result(url, body, "application/rss+xml")
        if url == UNKNOWN_DETAIL_URL:
            body = (FIXTURES / "detail_unknown_actor.html").read_text(
                encoding="utf-8"
            )
            return _result(url, body, "text/html")
        if url == UNKNOWN_ORIGINAL_URL:
            body = (FIXTURES / "original.html").read_text(encoding="utf-8")
            return _result(url, body, "text/html")
        raise AssertionError(f"unexpected URL: {url}")


def _result(url: str, body: str, content_type: str) -> FetchResult:
    return FetchResult(
        requested_url=url,
        final_url=url,
        status_code=200,
        body=body,
        content_sha256=hashlib.sha256(body.encode("utf-8")).hexdigest(),
        fetched_at=NOW.isoformat(),
        content_type=content_type,
    )


def _inputs(tmp_path: Path) -> tuple[Path, Path, Path]:
    organizations = tmp_path / "organizations.csv"
    organizations.write_text(
        "id,name,aliases\n53,Kimsuky,Black Banshee | APT43\n",
        encoding="utf-8",
        newline="\n",
    )
    events = tmp_path / "events.csv"
    events.write_text(
        "id,event_date,title,description,threat_type,"
        "organization_id,releasing_product,link\n",
        encoding="utf-8",
        newline="\n",
    )
    spec = tmp_path / "spec.md"
    spec.write_text(
        "schema_version record_type organization_id review_status "
        "evidence collected_at",
        encoding="utf-8",
        newline="\n",
    )
    return organizations, events, spec


def _args(
    tmp_path: Path,
    *,
    dry_run: bool,
) -> object:
    organizations, events, spec = _inputs(tmp_path)
    argv = [
        "--organizations",
        str(organizations),
        "--existing-events",
        str(events),
        "--spec",
        str(spec),
        "--start-date",
        "2026-07-23",
        "--end-date",
        "2026-07-23",
        "--output-root",
        str(tmp_path / "output"),
        "--state-file",
        str(tmp_path / "state" / "lazarus-day.json"),
        "--request-delay",
        "0",
    ]
    if dry_run:
        argv.append("--dry-run")
    return build_parser().parse_args(argv)


def test_dry_run_generates_utf8_jsonl_without_checkpoint_or_input_changes(
    tmp_path: Path,
) -> None:
    args = _args(tmp_path, dry_run=True)
    before = {
        path: path.read_bytes()
        for path in (args.organizations, args.existing_events, args.spec)
    }
    summary = run(
        args,
        client_factory=lambda **_kwargs: FixtureClient(),
        now=NOW,
    )
    assert summary["stats"]["accepted"] == 1
    assert summary["stats"]["needs_review"] == 0
    assert not args.state_file.exists()
    assert summary["checkpoint_updated"] is False
    for path, content in before.items():
        assert path.read_bytes() == content

    normalized_path = Path(summary["outputs"]["normalized"])
    raw = normalized_path.read_bytes()
    assert b"\r\n" not in raw
    event = json.loads(raw.decode("utf-8").strip())
    assert event["db_id"] is None
    assert event["organization_id"] == 53
    assert not {
        "event_type",
        "severity",
        "region",
        "latitude",
        "longitude",
        "created_at",
    }.intersection(event)


def test_checkpoint_updates_only_after_success_and_not_after_failure(
    tmp_path: Path,
) -> None:
    args = _args(tmp_path, dry_run=False)
    run(
        args,
        client_factory=lambda **_kwargs: FixtureClient(),
        now=NOW,
    )
    state_before = args.state_file.read_bytes()
    normalized_path = args.output_root / "normalized" / "lazarus-day.events.jsonl"
    normalized_before = normalized_path.read_bytes()
    state = json.loads(state_before.decode("utf-8"))
    assert state["last_success_at"] == NOW.isoformat()
    assert state["last_seen_report_date"] == "2026-07-23"

    with pytest.raises(CollectorError, match="未更新规范化输出和 checkpoint"):
        run(
            args,
            client_factory=lambda **_kwargs: FixtureClient(fail_detail=True),
            now=NOW.replace(hour=9),
        )
    assert args.state_file.read_bytes() == state_before
    assert normalized_path.read_bytes() == normalized_before


def test_unmatched_actor_is_written_to_review_and_unmatched_files(
    tmp_path: Path,
) -> None:
    args = _args(tmp_path, dry_run=True)
    summary = run(
        args,
        client_factory=lambda **_kwargs: UnknownActorClient(),
        now=NOW,
    )
    assert summary["stats"]["accepted"] == 0
    assert summary["stats"]["needs_review"] == 1
    assert summary["stats"]["unmatched"] == 1
    review_record = json.loads(
        Path(summary["outputs"]["needs_review"])
        .read_text(encoding="utf-8")
        .strip()
    )
    unmatched_record = json.loads(
        Path(summary["outputs"]["unmatched"])
        .read_text(encoding="utf-8")
        .strip()
    )
    assert review_record["organization_id"] is None
    assert unmatched_record["organization_id"] is None
    assert unmatched_record["organization_name"] == "NewCluster"


def test_api_invocation_manifest_preserves_failed_source_id(tmp_path: Path) -> None:
    args = _args(tmp_path, dry_run=False)
    args.invocation_id = "api-" + "a" * 32
    with pytest.raises(CollectorError):
        run(
            args,
            client_factory=lambda **_kwargs: FixtureClient(fail_detail=True),
            now=NOW,
        )
    _write_invocation_manifest(
        args, status="failed", summary=None, error="CollectorError"
    )
    manifest = json.loads(
        (
            args.output_root
            / "reports"
            / f"lazarus-day-run-{args.invocation_id}.json"
        ).read_text(encoding="utf-8")
    )
    assert manifest["items"] == [
        {
            "source_event_id": "kimsuky-phishing-fixture-AbC12",
            "status": "failed",
            "review_required": False,
            "event_candidate": True,
            "error_kind": "detail_fetch_or_parse",
            "error": "Native collection item failed.",
        }
    ]


def test_invocation_id_is_strict_and_optional(tmp_path: Path) -> None:
    args = _args(tmp_path, dry_run=True)
    assert args.invocation_id is None
    with pytest.raises(SystemExit):
        build_parser().parse_args(["--invocation-id", "short"])


def test_native_main_exit_code_contract(monkeypatch) -> None:
    @contextmanager
    def available(_path):
        yield

    @contextmanager
    def busy(_path):
        raise CollectorLockError("busy")
        yield

    monkeypatch.setattr(cli_module, "exclusive_collector_lock", available)
    monkeypatch.setattr(
        cli_module,
        "run",
        lambda *_args, **_kwargs: {
            "stats": {"accepted": 0, "needs_review": 0, "rejected": 0},
            "outputs": {},
        },
    )
    assert cli_module.main([]) == 0

    def fail(*_args, **_kwargs):
        raise CollectorError("technical failure")

    monkeypatch.setattr(cli_module, "run", fail)
    assert cli_module.main([]) == 1
    monkeypatch.setattr(cli_module, "exclusive_collector_lock", busy)
    assert cli_module.main([]) == 20
