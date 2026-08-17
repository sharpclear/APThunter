from __future__ import annotations

import base64
import csv
import hashlib
import hmac
import io
import json
import os
import re
import secrets
import subprocess
import sys
import threading
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol
from urllib.parse import quote

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Response, status
from pydantic import BaseModel, ConfigDict, Field

from .api_store import ApiStore, StoreConflict
from .matcher import read_text_compatible
from .normalizer import canonicalize_url
from .storage import sha256_file


PROJECT_ROOT = Path(__file__).resolve().parents[2]
RUN_ID_RE = re.compile(r"^[0-9a-f]{32}$")
INVOCATION_ID_RE = re.compile(r"^api-[0-9a-f]{32}$")
SOURCE_ID_RE = re.compile(r"^[A-Za-z0-9._~%\-]{1,512}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
TERMINAL_NATIVE_STATUSES = {
    "completed",
    "completed_with_review",
    "failed",
}
ITEM_STATUSES = {
    "completed",
    "completed_with_review",
    "manual_review",
    "failed",
}
SUCCESSFUL_ITEM_STATUSES = ITEM_STATUSES - {"failed"}


def _env_bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class ApiSettings:
    project_root: Path = PROJECT_ROOT
    database_path: Path | None = None
    api_key: str | None = None
    worker_enabled: bool = True
    worker_poll_seconds: float = 0.25
    busy_retry_seconds: int = 60
    worker_lease_seconds: float = 30.0
    python_executable: str = sys.executable

    def __post_init__(self) -> None:
        root = Path(self.project_root).resolve()
        object.__setattr__(self, "project_root", root)
        database = self.database_path or (
            root / "data" / "events" / "state" / "api" / "lazarus-day-api.db"
        )
        object.__setattr__(self, "database_path", Path(database).resolve())

    @classmethod
    def from_env(cls) -> "ApiSettings":
        root = Path(
            os.environ.get("LAZARUS_DAY_PROJECT_ROOT", PROJECT_ROOT)
        ).resolve()
        database = os.environ.get("LAZARUS_DAY_API_DB")
        return cls(
            project_root=root,
            database_path=Path(database).resolve() if database else None,
            api_key=(
                os.environ.get("LAZARUS_DAY_API_KEY")
                or os.environ.get("EVENT_COLLECTOR_API_KEY")
                or None
            ),
            worker_enabled=_env_bool("LAZARUS_DAY_API_WORKER", True),
            worker_poll_seconds=float(
                os.environ.get("LAZARUS_DAY_API_POLL_SECONDS", "0.25")
            ),
            busy_retry_seconds=int(
                os.environ.get("LAZARUS_DAY_API_BUSY_RETRY_SECONDS", "60")
            ),
            worker_lease_seconds=float(
                os.environ.get("LAZARUS_DAY_API_LEASE_SECONDS", "30")
            ),
        )

    @property
    def events_root(self) -> Path:
        return self.project_root / "data" / "events"

    @property
    def reference_events_path(self) -> Path:
        return self.project_root / "data" / "reference" / "apt_events.csv"

    @property
    def organizations_path(self) -> Path:
        return self.project_root / "data" / "reference" / "apt_organizations.csv"

    @property
    def spec_path(self) -> Path:
        return self.project_root / "docs" / "APT事件数据采集及导入格式规范.md"

    @property
    def collector_path(self) -> Path:
        return self.project_root / "scripts" / "collect_lazarus_day.py"

    @property
    def api_runs_root(self) -> Path:
        return self.events_root / "api-runs"

    @property
    def api_state_path(self) -> Path:
        return self.events_root / "state" / "lazarus-day-api.json"

    @property
    def api_log_root(self) -> Path:
        return self.project_root / "logs" / "api"


@dataclass(frozen=True)
class RunResult:
    exit_code: int
    manifest_path: Path
    log_path: Path


class PipelineRunner(Protocol):
    def run(
        self,
        run: Mapping[str, Any],
        on_started: Callable[[int, Path, Path], None],
    ) -> RunResult: ...


class FixedCollectorRunner:
    """Run only the reviewed collector entry with a fixed argument list."""

    def __init__(self, settings: ApiSettings) -> None:
        self.settings = settings

    def run(
        self,
        run: Mapping[str, Any],
        on_started: Callable[[int, Path, Path], None],
    ) -> RunResult:
        invocation_id = str(run["invocation_id"])
        if not INVOCATION_ID_RE.fullmatch(invocation_id):
            raise ValueError("invalid persisted invocation ID")
        output_root = self.settings.api_runs_root / invocation_id
        manifest_path = (
            output_root
            / "reports"
            / f"lazarus-day-run-{invocation_id}.json"
        )
        self.settings.api_log_root.mkdir(parents=True, exist_ok=True)
        output_root.mkdir(parents=True, exist_ok=True)
        log_path = self.settings.api_log_root / f"{invocation_id}.log"
        if manifest_path.is_file():
            try:
                manifest = _read_json(manifest_path)
                if (
                    manifest.get("invocation_id") == invocation_id
                    and manifest.get("status") in TERMINAL_NATIVE_STATUSES
                ):
                    on_started(0, log_path, manifest_path)
                    return RunResult(
                        0 if manifest["status"] != "failed" else 1,
                        manifest_path,
                        log_path,
                    )
            except (OSError, ValueError, json.JSONDecodeError):
                pass
        argv = [
            self.settings.python_executable,
            str(self.settings.collector_path),
            "--organizations",
            str(self.settings.organizations_path),
            "--existing-events",
            str(self.settings.reference_events_path),
            "--spec",
            str(self.settings.spec_path),
            "--since-last-success",
            "--max-pages",
            "10",
            "--max-items",
            "500",
            "--request-delay",
            "1",
            "--timeout",
            "20",
            "--output-root",
            str(output_root),
            "--state-file",
            str(self.settings.api_state_path),
            "--invocation-id",
            invocation_id,
            "--log-level",
            "INFO",
        ]
        creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        with log_path.open("ab", buffering=0) as log_handle:
            process = subprocess.Popen(
                argv,
                cwd=str(self.settings.project_root),
                stdin=subprocess.DEVNULL,
                stdout=log_handle,
                stderr=subprocess.STDOUT,
                shell=False,
                creationflags=creation_flags,
            )
            on_started(process.pid, log_path, manifest_path)
            exit_code = process.wait()
        return RunResult(exit_code, manifest_path, log_path)


class RunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mode: str = Field(default="incremental", pattern=r"^incremental$")


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("JSON artifact must contain an object")
    return value


def _safe_relpath(path: Path, root: Path) -> str:
    return path.resolve(strict=True).relative_to(
        root.resolve(strict=True)
    ).as_posix()


def _safe_indexed_path(
    settings: ApiSettings, relative_path: str, allowed_root: Path
) -> Path:
    candidate = Path(relative_path)
    if not relative_path or candidate.is_absolute():
        raise ValueError("invalid indexed path")
    resolved = (settings.project_root / candidate).resolve(strict=True)
    resolved.relative_to(allowed_root.resolve(strict=True))
    return resolved


def _normalized_source_url(value: Any) -> str:
    text = str(value or "").strip()
    return canonicalize_url(text) if text else ""


def _variant_key(value: Mapping[str, Any]) -> str:
    event_key = str(value.get("event_key") or "").strip()
    if event_key:
        return event_key
    material = "\n".join(
        str(value.get(key) or "").strip()
        for key in (
            "organization_id",
            "event_date",
            "link",
            "title",
        )
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _variant_from_mapping(
    value: Mapping[str, Any], *, accepted: bool
) -> dict[str, Any]:
    evidence: Any = value.get("evidence") or []
    if value.get("evidence_json"):
        try:
            evidence = json.loads(str(value["evidence_json"]))
        except json.JSONDecodeError:
            evidence = []
    review_reasons = value.get("review_reasons") or []
    if isinstance(review_reasons, str):
        review_reasons = [
            item.strip() for item in review_reasons.split("|") if item.strip()
        ]
    return {
        "event_key": _variant_key(value),
        "event_date": value.get("event_date") or None,
        "date_precision": value.get("date_precision") or None,
        "title": value.get("title") or None,
        "description": value.get("description") or None,
        "threat_type": value.get("threat_type") or None,
        "organization_id": value.get("organization_id") or None,
        "organization_name": value.get("organization_name") or None,
        "releasing_product": value.get("releasing_product") or None,
        "link": value.get("link") or None,
        "confidence": value.get("confidence") or None,
        "review_status": "accepted" if accepted else "needs_review",
        "review_reasons": review_reasons,
        "evidence": evidence if isinstance(evidence, list) else [],
    }


def _review_priority(path: Path, accepted: bool) -> int:
    name = path.name.lower()
    priority = 1000 if accepted else 0
    if ".review.display.csv" in name:
        priority += 500
    elif "complete-2026-08-03" in name:
        priority += 400
    elif "total-2026-08-03" in name:
        priority += 300
    elif "alias-corrected" in name:
        priority += 200
    else:
        priority += 100
    return priority


def _load_review_variants(
    settings: ApiSettings,
) -> dict[str, dict[str, tuple[int, dict[str, Any]]]]:
    by_url: dict[str, dict[str, tuple[int, dict[str, Any]]]] = {}
    for path in sorted(settings.events_root.rglob("*.review*.csv")):
        try:
            text, _encoding = read_text_compatible(path)
            rows = csv.DictReader(io.StringIO(text, newline=""))
            for row in rows:
                source_url = _normalized_source_url(row.get("lazarus_day_url"))
                if not source_url:
                    continue
                decision = str(row.get("review_decision") or "").strip()
                if decision in {"拒绝", "reject", "rejected"}:
                    continue
                accepted = decision in {"接受", "accept", "accepted"}
                variant = _variant_from_mapping(row, accepted=accepted)
                priority = _review_priority(path, accepted)
                current = by_url.setdefault(source_url, {}).get(
                    variant["event_key"]
                )
                if current is None or priority > current[0]:
                    by_url[source_url][variant["event_key"]] = (
                        priority,
                        variant,
                    )
        except (OSError, UnicodeError, csv.Error):
            continue
    for path in sorted(settings.events_root.rglob("*.events.jsonl")):
        if path.name.endswith(".raw.jsonl"):
            continue
        try:
            for line in path.read_text(encoding="utf-8-sig").splitlines():
                if not line.strip():
                    continue
                row = json.loads(line)
                if not isinstance(row, dict):
                    continue
                context = row.get("review_context") or {}
                source_url = _normalized_source_url(
                    context.get("lazarus_day_url")
                )
                if not source_url:
                    continue
                accepted = row.get("review_status") == "accepted"
                variant = _variant_from_mapping(row, accepted=accepted)
                priority = 50 + (1000 if accepted else 0)
                current = by_url.setdefault(source_url, {}).get(
                    variant["event_key"]
                )
                if current is None or priority > current[0]:
                    by_url[source_url][variant["event_key"]] = (
                        priority,
                        variant,
                    )
        except (OSError, UnicodeError, json.JSONDecodeError):
            continue
    return by_url


def _load_reference_variants(
    settings: ApiSettings,
    source_urls: set[str],
) -> dict[str, dict[str, tuple[int, dict[str, Any]]]]:
    result: dict[str, dict[str, tuple[int, dict[str, Any]]]] = {}
    if not settings.reference_events_path.is_file():
        return result
    text, _encoding = read_text_compatible(settings.reference_events_path)
    for row in csv.DictReader(io.StringIO(text, newline="")):
        link = _normalized_source_url(row.get("link"))
        if not link or link not in source_urls:
            continue
        variant = _variant_from_mapping(row, accepted=True)
        result.setdefault(link, {})[variant["event_key"]] = (2000, variant)
    return result


def _read_raw_observations(
    settings: ApiSettings,
) -> tuple[dict[str, dict[str, Any]], list[dict[str, str]]]:
    observations: dict[str, dict[str, Any]] = {}
    errors: list[dict[str, str]] = []
    if not settings.events_root.exists():
        return observations, errors
    root = settings.events_root.resolve(strict=True)
    for path in sorted(settings.events_root.rglob("*.raw.jsonl")):
        if ".failed-" in path.name:
            # Failure artifacts are retry diagnostics, not event products.
            # Their item identities are carried by the native run manifest.
            continue
        try:
            resolved = path.resolve(strict=True)
            resolved.relative_to(root)
            lines = resolved.read_bytes().splitlines()
            for line_number, line_bytes in enumerate(lines, 1):
                if not line_bytes.strip():
                    continue
                row = json.loads(line_bytes.decode("utf-8"))
                if not isinstance(row, dict):
                    continue
                source_id = str(row.get("source_record_id") or "")
                if not SOURCE_ID_RE.fullmatch(source_id):
                    continue
                html = row.get("raw_detail_html")
                content_sha = str(row.get("content_sha256") or "").lower()
                if not isinstance(html, str) or not SHA256_RE.fullmatch(content_sha):
                    raise ValueError("raw content identity is missing")
                if hashlib.sha256(html.encode("utf-8")).hexdigest() != content_sha:
                    raise ValueError("raw content hash mismatch")
                observation = {
                    "row": row,
                    "path": resolved,
                    "line": line_number,
                    "line_sha256": hashlib.sha256(line_bytes).hexdigest(),
                }
                previous = observations.get(source_id)
                order = (
                    str(row.get("fetched_at") or ""),
                    resolved.as_posix(),
                    line_number,
                )
                if previous is None or order > previous["order"]:
                    observation["order"] = order
                    observations[source_id] = observation
        except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
            errors.append(
                {"artifact": path.name, "error": type(exc).__name__}
            )
    return observations, errors


def _event_product(
    settings: ApiSettings,
    source_id: str,
    observation: Mapping[str, Any],
    variants: list[dict[str, Any]],
) -> dict[str, Any] | None:
    raw = dict(observation["row"])
    if raw.get("classification") == "rejected":
        return None
    if raw.get("dedup_status") == "exact_duplicate":
        return None
    accepted = [v for v in variants if v["review_status"] == "accepted"]
    pending = [v for v in variants if v["review_status"] != "accepted"]
    if not variants:
        pending = [
            {
                "event_key": raw.get("event_key"),
                "event_date": raw.get("published_date"),
                "date_precision": raw.get("date_precision"),
                "title": raw.get("raw_title"),
                "description": raw.get("raw_summary"),
                "threat_type": None,
                "organization_id": None,
                "organization_name": None,
                "releasing_product": raw.get("publisher"),
                "link": raw.get("original_url") or raw.get("lazarus_day_url"),
                "confidence": None,
                "review_status": "needs_review",
                "review_reasons": ["No completed review snapshot is indexed."],
                "evidence": [],
            }
        ]
        variants = pending
    if accepted and not pending:
        quality_status = "accepted"
        review_required = False
    elif accepted:
        quality_status = "accepted_with_review"
        review_required = True
    else:
        quality_status = "needs_review"
        review_required = True
    organizations = {
        (str(v.get("organization_id") or ""), str(v.get("organization_name") or ""))
        for v in accepted
        if v.get("organization_id")
    }
    organization_id: str | None = None
    organization_name: str | None = None
    if len(organizations) == 1:
        organization_id, organization_name = next(iter(organizations))
    primary = accepted[0] if accepted else variants[0]
    event_dates = {str(v.get("event_date")) for v in accepted if v.get("event_date")}
    evidence = [item for variant in variants for item in variant.get("evidence", [])]
    provenance = {
        "source_record_id": source_id,
        "lazarus_day_url": raw.get("lazarus_day_url"),
        "original_url": raw.get("original_url"),
        "publisher": raw.get("publisher"),
        "raw_content_sha256": raw.get("content_sha256"),
        "fetched_at": raw.get("fetched_at"),
    }
    quality_reasons = list(
        dict.fromkeys(
            [
                str(reason)
                for variant in pending
                for reason in variant.get("review_reasons", [])
                if reason
            ]
            + [str(item) for item in raw.get("parse_warnings", []) if item]
            + ([str(raw["dedup_reason"])] if raw.get("dedup_reason") else [])
        )
    )
    structured = {
        "related_actors": raw.get("raw_related_actors") or [],
        "tags": raw.get("raw_tags") or [],
        "variants": variants,
    }
    quality = {
        "status": quality_status,
        "review_required": review_required,
        "reasons": quality_reasons,
        "accepted_variants": len(accepted),
        "pending_variants": len(pending),
        "match_status": raw.get("match_status"),
        "dedup_status": raw.get("dedup_status"),
    }
    stable_provenance = {
        key: value for key, value in provenance.items() if key != "fetched_at"
    }
    digest_value = {
        "source_event_id": source_id,
        "content_sha256": raw["content_sha256"],
        "title": primary.get("title") or raw.get("raw_title"),
        "description": primary.get("description") or raw.get("raw_summary"),
        "quality_status": quality_status,
        "structured": structured,
        "evidence": evidence,
        # A repeat fetch timestamp is operational metadata, not a content
        # revision. It must not create a new event version/change record.
        "provenance": stable_provenance,
        "quality": quality,
    }
    product_digest = hashlib.sha256(
        json.dumps(
            digest_value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    raw_path = Path(observation["path"])
    return {
        "source_event_id": source_id,
        "source": "lazarus.day",
        "source_record_id": source_id,
        "source_url": raw.get("lazarus_day_url"),
        "original_url": raw.get("original_url"),
        "content_sha256": raw["content_sha256"],
        "product_digest": product_digest,
        "title": primary.get("title") or raw.get("raw_title") or "Untitled report",
        "description": primary.get("description") or raw.get("raw_summary"),
        "event_time": next(iter(event_dates)) if len(event_dates) == 1 else None,
        "report_time": raw.get("published_date"),
        "collected_at": raw.get("fetched_at"),
        "quality_status": quality_status,
        "review_required": review_required,
        "organization_id": organization_id,
        "organization_name": organization_name,
        "threat_type": primary.get("threat_type"),
        "releasing_product": primary.get("releasing_product") or raw.get("publisher"),
        "primary_link": primary.get("link") or raw.get("original_url") or raw.get("lazarus_day_url"),
        "structured": structured,
        "evidence": evidence,
        "provenance": provenance,
        "quality": quality,
        "raw_relpath": _safe_relpath(raw_path, settings.project_root),
        "raw_line": observation["line"],
        "raw_line_sha256": observation["line_sha256"],
    }


def index_events(
    settings: ApiSettings, store: ApiStore, run_id: str | None = None
) -> dict[str, Any]:
    observations, errors = _read_raw_observations(settings)
    source_urls: set[str] = set()
    for observation in observations.values():
        raw = observation["row"]
        for key in ("lazarus_day_url", "original_url", "final_url"):
            url = _normalized_source_url(raw.get(key))
            if url:
                source_urls.add(url)
    variants_by_url = _load_review_variants(settings)
    reference_variants = _load_reference_variants(settings, source_urls)
    for url, values in reference_variants.items():
        bucket = variants_by_url.setdefault(url, {})
        for event_key, candidate in values.items():
            current = bucket.get(event_key)
            if current is None or candidate[0] > current[0]:
                bucket[event_key] = candidate

    indexed: list[str] = []
    changed: list[str] = []
    for source_id, observation in sorted(observations.items()):
        raw = observation["row"]
        gathered: dict[str, tuple[int, dict[str, Any]]] = {}
        for key in ("lazarus_day_url", "original_url", "final_url"):
            url = _normalized_source_url(raw.get(key))
            for event_key, candidate in variants_by_url.get(url, {}).items():
                current = gathered.get(event_key)
                if current is None or candidate[0] > current[0]:
                    gathered[event_key] = candidate
        semantic_variants: dict[
            tuple[str, str, str], tuple[int, dict[str, Any]]
        ] = {}
        for candidate in gathered.values():
            variant = candidate[1]
            slot = (
                str(variant.get("organization_id") or ""),
                str(variant.get("event_date") or ""),
                _normalized_source_url(variant.get("link")),
            )
            current = semantic_variants.get(slot)
            if current is None or candidate[0] > current[0]:
                semantic_variants[slot] = candidate
        variants = [
            candidate[1]
            for candidate in sorted(
                semantic_variants.values(),
                key=lambda item: (
                    str(item[1].get("organization_id") or ""),
                    str(item[1].get("event_date") or ""),
                    item[1]["event_key"],
                ),
            )
        ]
        try:
            product = _event_product(
                settings, source_id, observation, variants
            )
            if product is None:
                continue
            indexed.append(source_id)
            if store.upsert_event(product, run_id=run_id):
                changed.append(source_id)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            errors.append(
                {"artifact": source_id, "error": type(exc).__name__}
            )
    return {
        "indexed": len(indexed),
        "indexed_source_ids": indexed,
        "changed": len(changed),
        "changed_source_ids": changed,
        "errors": errors,
    }


def _manifest_result(
    path: Path, expected_invocation_id: str
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    manifest = _read_json(path.resolve(strict=True))
    if manifest.get("invocation_id") != expected_invocation_id:
        raise ValueError("native manifest invocation ID mismatch")
    native_status = str(manifest.get("status") or "")
    if native_status not in TERMINAL_NATIVE_STATUSES:
        raise ValueError("native manifest is not terminal")
    current = manifest.get("items") or []
    recovery = manifest.get("recovery_items") or []
    if not isinstance(current, list) or not isinstance(recovery, list):
        raise ValueError("native manifest item collections must be arrays")
    items: list[dict[str, Any]] = []
    seen: set[str] = set()
    for origin, value in (
        [("current", item) for item in current]
        + [("recovery", item) for item in recovery]
    ):
        if not isinstance(value, dict):
            raise ValueError("invalid native item")
        if not bool(value.get("event_candidate", True)):
            continue
        source_id = str(value.get("source_event_id") or "")
        if not SOURCE_ID_RE.fullmatch(source_id) or source_id in seen:
            raise ValueError("invalid or duplicate source event ID")
        item_status = str(value.get("status") or "")
        if item_status not in ITEM_STATUSES:
            raise ValueError("invalid native item status")
        seen.add(source_id)
        items.append(
            {
                "source_event_id": source_id,
                "origin": origin,
                "status": item_status,
                "review_required": bool(value.get("review_required"))
                or item_status
                in {"completed_with_review", "manual_review"},
                "error_kind": value.get("error_kind"),
                "error": value.get("error"),
            }
        )
    return manifest, items


class PipelineWorker:
    def __init__(
        self,
        settings: ApiSettings,
        store: ApiStore,
        runner: PipelineRunner,
    ) -> None:
        self.settings = settings
        self.store = store
        self.runner = runner
        self.worker_id = uuid.uuid4().hex
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(
            target=self._loop, name="lazarus-day-api-worker", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()
        if self._thread is not None:
            self._thread.join(timeout=5)

    def notify(self) -> None:
        self._wake.set()

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                run = self.store.claim_next_run(
                    self.worker_id,
                    lease_seconds=self.settings.worker_lease_seconds,
                )
            except Exception:
                self._wake.wait(self.settings.worker_poll_seconds)
                self._wake.clear()
                continue
            if run is None:
                self._wake.wait(self.settings.worker_poll_seconds)
                self._wake.clear()
                continue
            try:
                self._execute(run)
            except Exception as exc:
                try:
                    self.store.finish_run(
                        str(run["id"]),
                        status="failed",
                        exit_code=None,
                        native_status=None,
                        native_invocation_id=str(run.get("invocation_id") or ""),
                        error=f"worker failed: {type(exc).__name__}",
                        worker_id=self.worker_id,
                    )
                except Exception:
                    pass

    def _execute(self, run: Mapping[str, Any]) -> None:
        run_id = str(run["id"])
        invocation_id = str(run["invocation_id"])

        def on_started(pid: int, log: Path, manifest: Path) -> None:
            self.store.set_run_process(
                run_id,
                self.worker_id,
                pid=pid,
                log_relpath=log.resolve().relative_to(
                    self.settings.project_root
                ).as_posix(),
                manifest_relpath=manifest.resolve().relative_to(
                    self.settings.project_root
                ).as_posix(),
            )

        heartbeat_stop = threading.Event()

        def heartbeat() -> None:
            interval = max(0.1, self.settings.worker_lease_seconds / 3)
            while not heartbeat_stop.wait(interval):
                if not self.store.heartbeat(
                    run_id,
                    self.worker_id,
                    lease_seconds=self.settings.worker_lease_seconds,
                ):
                    return

        heartbeat_thread = threading.Thread(target=heartbeat, daemon=True)
        heartbeat_thread.start()
        try:
            result = self.runner.run(run, on_started)
        except Exception as exc:
            self.store.finish_run(
                run_id,
                status="failed",
                exit_code=None,
                native_status=None,
                native_invocation_id=invocation_id,
                error=f"collector process failed: {type(exc).__name__}",
                worker_id=self.worker_id,
            )
            return
        finally:
            heartbeat_stop.set()
            heartbeat_thread.join(timeout=1)
        if result.exit_code == 20:
            available = datetime.now(timezone.utc) + timedelta(
                seconds=self.settings.busy_retry_seconds
            )
            self.store.reschedule_run(
                run_id,
                self.worker_id,
                available_at=available.isoformat().replace("+00:00", "Z"),
                error="collector lock is busy; retry scheduled",
            )
            return

        native_status: str | None = None
        items: list[dict[str, Any]] = []
        error: str | None = None
        try:
            manifest, items = _manifest_result(
                result.manifest_path, invocation_id
            )
            native_status = str(manifest["status"])
        except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
            error = f"native manifest validation failed: {type(exc).__name__}"

        existing_before = {
            item["source_event_id"]: self.store.get_event(
                item["source_event_id"]
            )
            for item in items
        }
        indexing = index_events(self.settings, self.store, run_id=run_id)
        indexed_ids = set(indexing["indexed_source_ids"])
        finalized_items: list[dict[str, Any]] = []
        for item in items:
            item = dict(item)
            source_id = item["source_event_id"]
            if (
                item["status"] in SUCCESSFUL_ITEM_STATUSES
                and source_id not in indexed_ids
            ):
                item["status"] = "failed"
                item["error_kind"] = "missing_indexed_event"
                item["error"] = "event product is unavailable"
            if item["status"] in SUCCESSFUL_ITEM_STATUSES:
                if item["origin"] == "recovery" or self.store.failed_before(
                    source_id, run_id
                ):
                    item["origin"] = "recovery"
                elif existing_before[source_id] is None:
                    item["origin"] = "new"
                else:
                    item["origin"] = "current"
            finalized_items.append(item)
        self.store.replace_run_items(run_id, finalized_items)

        counts = {
            "discovered": len(finalized_items),
            "new": sum(i["origin"] == "new" for i in finalized_items),
            "recovered": sum(
                i["origin"] == "recovery" for i in finalized_items
            ),
            "completed": sum(
                i["status"] == "completed" for i in finalized_items
            ),
            "completed_with_review": sum(
                i["status"] == "completed_with_review"
                for i in finalized_items
            ),
            "manual_review": sum(
                i["status"] == "manual_review" for i in finalized_items
            ),
            "failed": sum(i["status"] == "failed" for i in finalized_items),
        }
        if indexing["errors"]:
            error = f"{len(indexing['errors'])} event artifact(s) failed validation"
        if (
            result.exit_code == 0
            and error is None
            and native_status in {"completed", "completed_with_review"}
            and not counts["failed"]
        ):
            final_status = (
                "completed_with_review"
                if native_status == "completed_with_review"
                or counts["completed_with_review"]
                or counts["manual_review"]
                else "completed"
            )
        else:
            final_status = "failed"
            if error is None:
                error = f"collector exited with code {result.exit_code}"
        self.store.finish_run(
            run_id,
            status=final_status,
            exit_code=result.exit_code,
            native_status=native_status,
            native_invocation_id=invocation_id,
            error=error,
            counts=counts,
            worker_id=self.worker_id,
        )


def _cursor_secret(store: ApiStore) -> bytes:
    value = store.set_meta_if_absent("cursor_secret", secrets.token_hex(32))
    return bytes.fromhex(value)


def _cursor_instance(store: ApiStore) -> str:
    return store.set_meta_if_absent("instance_id", str(uuid.uuid4()))


def _encode_cursor(store: ApiStore, after_seq: int) -> str:
    payload = json.dumps(
        {
            "v": 1,
            "instance": _cursor_instance(store),
            "feed": "events",
            "after": after_seq,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    signature = hmac.new(_cursor_secret(store), payload, hashlib.sha256).digest()
    left = base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")
    right = base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")
    return f"{left}.{right}"


def _decode_cursor(store: ApiStore, token: str | None) -> int:
    if not token:
        return 0
    try:
        left, right = token.split(".", 1)
        payload = base64.urlsafe_b64decode(left + "=" * (-len(left) % 4))
        signature = base64.urlsafe_b64decode(right + "=" * (-len(right) % 4))
        expected = hmac.new(_cursor_secret(store), payload, hashlib.sha256).digest()
        if not hmac.compare_digest(signature, expected):
            raise ValueError("signature")
        value = json.loads(payload)
        if value != {
            "v": 1,
            "instance": _cursor_instance(store),
            "feed": "events",
            "after": value.get("after"),
        }:
            raise ValueError("scope")
        after = value["after"]
        if not isinstance(after, int) or after < 0:
            raise ValueError("position")
        return after
    except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise HTTPException(
            status_code=400,
            detail={
                "code": "invalid_cursor",
                "message": "Cursor is invalid or expired.",
            },
        ) from exc


def _event_path(source_id: str) -> str:
    return quote(source_id, safe="")


def _json_field(row: Mapping[str, Any], name: str, default: Any) -> Any:
    try:
        return json.loads(str(row.get(name) or ""))
    except (json.JSONDecodeError, TypeError):
        return default


def _public_event(
    row: Mapping[str, Any], *, change: bool = False
) -> dict[str, Any]:
    source_id = str(row["source_event_id"])
    encoded = _event_path(source_id)
    value: dict[str, Any] = {
        "source": row["source"],
        "source_event_id": source_id,
        "version": row["version"],
        "title": row["title"],
        "description": row.get("description"),
        "event_time": row.get("event_time"),
        "report_time": row.get("report_time"),
        "collected_at": row.get("collected_at"),
        "updated_at": row["updated_at"],
        "quality_status": row["quality_status"],
        "review_required": bool(row["review_required"]),
        "source_url": row["source_url"],
        "original_source_url": row.get("original_url"),
        "organization": {
            "id": row.get("organization_id"),
            "name": row.get("organization_name"),
        },
        "threat_type": row.get("threat_type"),
        "releasing_product": row.get("releasing_product"),
        "primary_link": row.get("primary_link"),
        "structured_event": _json_field(row, "structured_json", {}),
        "evidence": _json_field(row, "evidence_json", []),
        "provenance": _json_field(row, "provenance_json", {}),
        "links": {
            "self": f"/api/v1/events/{encoded}",
            "raw": f"/api/v1/events/{encoded}/raw",
            "quality": f"/api/v1/events/{encoded}/quality",
            "evidence": f"/api/v1/events/{encoded}/evidence",
        },
    }
    if change:
        value["change"] = {
            "seq": row["change_seq"],
            "operation": row["operation"],
            "version": row["change_version"],
            "changed_at": row["changed_at"],
        }
    return value


def _public_run(row: Mapping[str, Any]) -> dict[str, Any]:
    run_id = str(row["id"])
    value: dict[str, Any] = {
        "id": run_id,
        "mode": row["mode"],
        "status": row["status"],
        "created_at": row["created_at"],
        "started_at": row.get("started_at"),
        "completed_at": row.get("completed_at"),
        "updated_at": row["updated_at"],
        "attempts": row["attempts"],
        "counts": {
            "discovered": row["discovered_count"],
            "new": row["new_count"],
            "recovered": row["recovered_count"],
            "completed": row["completed_count"],
            "completed_with_review": row[
                "completed_with_review_count"
            ],
            "manual_review": row["manual_review_count"],
            "failed": row["failed_count"],
        },
        "links": {
            "self": f"/api/v1/runs/{run_id}",
            "events": f"/api/v1/runs/{run_id}/events",
        },
    }
    if row.get("error"):
        value["error"] = {"message": str(row["error"])}
    return value


def _normalize_source_id(value: str) -> str:
    if not SOURCE_ID_RE.fullmatch(value):
        raise HTTPException(
            status_code=422,
            detail={
                "code": "invalid_source_event_id",
                "message": "A complete Lazarus.day source event ID is required.",
            },
        )
    return value


def _read_indexed_raw(
    settings: ApiSettings, row: Mapping[str, Any]
) -> dict[str, Any]:
    path = _safe_indexed_path(
        settings, str(row["raw_relpath"]), settings.events_root
    )
    lines = path.read_bytes().splitlines()
    line_number = int(row["raw_line"])
    if line_number < 1 or line_number > len(lines):
        raise ValueError("raw line is missing")
    line = lines[line_number - 1]
    if hashlib.sha256(line).hexdigest() != row["raw_line_sha256"]:
        raise ValueError("raw line hash mismatch")
    value = json.loads(line.decode("utf-8"))
    if value.get("source_record_id") != row["source_event_id"]:
        raise ValueError("raw source identity mismatch")
    html = value.get("raw_detail_html")
    if not isinstance(html, str):
        raise ValueError("raw page content is missing")
    if hashlib.sha256(html.encode("utf-8")).hexdigest() != row["content_sha256"]:
        raise ValueError("raw page hash mismatch")
    return value


def create_app(
    settings: ApiSettings | None = None,
    store: ApiStore | None = None,
    runner: PipelineRunner | None = None,
) -> FastAPI:
    settings = settings or ApiSettings.from_env()
    store = store or ApiStore(settings.database_path)  # type: ignore[arg-type]
    runner = runner or FixedCollectorRunner(settings)
    worker = PipelineWorker(settings, store, runner)

    @asynccontextmanager
    async def lifespan(application: FastAPI):
        store.initialize()
        initial_index = index_events(settings, store)
        application.state.initial_index = initial_index
        if settings.worker_enabled:
            worker.start()
        try:
            yield
        finally:
            worker.stop()

    application = FastAPI(
        title="Lazarus.day Event Collector API",
        version="1.0.0",
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    application.state.settings = settings
    application.state.store = store
    application.state.worker = worker

    def require_api_key(
        x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    ) -> None:
        expected = settings.api_key
        if not expected:
            raise HTTPException(
                status_code=503,
                detail={
                    "code": "api_key_not_configured",
                    "message": "API key is not configured.",
                },
            )
        if not x_api_key or not secrets.compare_digest(x_api_key, expected):
            raise HTTPException(
                status_code=401,
                detail={
                    "code": "unauthorized",
                    "message": "A valid API key is required.",
                },
                headers={"WWW-Authenticate": "ApiKey"},
            )

    protected = [Depends(require_api_key)]

    @application.get("/healthz", include_in_schema=False)
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @application.get("/readyz", dependencies=protected)
    def readyz(response: Response) -> dict[str, Any]:
        initial = getattr(application.state, "initial_index", {})
        checks = {
            "database": store.ping(),
            "collector_entry": settings.collector_path.is_file(),
            "organizations": settings.organizations_path.is_file(),
            "reference_events": settings.reference_events_path.is_file(),
            "events_root": settings.events_root.is_dir(),
            "artifact_index": not bool(initial.get("errors", [])),
        }
        ready = all(checks.values())
        if not ready:
            response.status_code = 503
        return {
            "status": "ready" if ready else "not_ready",
            "checks": checks,
            "indexed_events": store.count_events() if checks["database"] else 0,
        }

    @application.post(
        "/api/v1/runs",
        status_code=status.HTTP_202_ACCEPTED,
        dependencies=protected,
    )
    def create_run(
        request: RunRequest,
        response: Response,
        idempotency_key: str | None = Header(
            default=None, alias="Idempotency-Key"
        ),
    ) -> dict[str, Any]:
        if idempotency_key is not None:
            idempotency_key = idempotency_key.strip()
            if not idempotency_key or len(idempotency_key) > 128:
                raise HTTPException(
                    status_code=422,
                    detail={
                        "code": "invalid_idempotency_key",
                        "message": "Idempotency-Key must be 1-128 characters.",
                    },
                )
        run_id = uuid.uuid4().hex
        try:
            row, created = store.create_run(
                run_id=run_id,
                invocation_id=f"api-{run_id}",
                idempotency_key=idempotency_key,
                request=request.model_dump(),
            )
        except StoreConflict as exc:
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "run_already_active",
                    "message": "An incremental collection run is already active.",
                    "run_id": exc.active_run_id,
                },
            ) from exc
        response.headers["Location"] = f"/api/v1/runs/{row['id']}"
        response.headers["Idempotent-Replay"] = "false" if created else "true"
        if created:
            worker.notify()
        return _public_run(row)

    @application.get("/api/v1/runs", dependencies=protected)
    def list_runs(
        limit: int = Query(default=50, ge=1, le=200)
    ) -> dict[str, Any]:
        return {"items": [_public_run(row) for row in store.list_runs(limit)]}

    def run_row(run_id: str) -> dict[str, Any]:
        if not RUN_ID_RE.fullmatch(run_id):
            raise HTTPException(status_code=404, detail={"code": "run_not_found"})
        row = store.get_run(run_id)
        if row is None:
            raise HTTPException(status_code=404, detail={"code": "run_not_found"})
        return row

    @application.get("/api/v1/runs/{run_id}", dependencies=protected)
    def get_run(run_id: str) -> dict[str, Any]:
        return _public_run(run_row(run_id))

    @application.get(
        "/api/v1/runs/{run_id}/events", dependencies=protected
    )
    def get_run_events(run_id: str) -> dict[str, Any]:
        run_row(run_id)
        values = []
        for item in store.list_run_items(run_id):
            event = store.get_event(item["source_event_id"])
            values.append(
                {
                    "source_event_id": item["source_event_id"],
                    "origin": item["origin"],
                    "status": item["status"],
                    "review_required": bool(item["review_required"]),
                    "error": (
                        {"message": "Item processing failed; inspect the collector log."}
                        if item.get("error")
                        else None
                    ),
                    "event": _public_event(event) if event else None,
                }
            )
        return {"run_id": run_id, "items": values}

    @application.get("/api/v1/events", dependencies=protected)
    def list_events(
        cursor: str | None = Query(default=None),
        limit: int = Query(default=50, ge=1, le=200),
    ) -> dict[str, Any]:
        after = _decode_cursor(store, cursor)
        rows, has_more = store.list_changes(after, limit)
        next_seq = int(rows[-1]["change_seq"]) if rows else after
        return {
            "items": [_public_event(row, change=True) for row in rows],
            "next_cursor": _encode_cursor(store, next_seq),
            "has_more": has_more,
        }

    def event_row(source_id: str) -> tuple[str, dict[str, Any]]:
        normalized = _normalize_source_id(source_id)
        row = store.get_event(normalized)
        if row is None:
            raise HTTPException(
                status_code=404, detail={"code": "event_not_found"}
            )
        return normalized, row

    @application.get("/api/v1/events/{source_id}", dependencies=protected)
    def get_event(source_id: str) -> dict[str, Any]:
        _, row = event_row(source_id)
        return _public_event(row)

    @application.get(
        "/api/v1/events/{source_id}/raw", dependencies=protected
    )
    def get_raw(source_id: str) -> dict[str, Any]:
        normalized, row = event_row(source_id)
        try:
            raw = _read_indexed_raw(settings, row)
        except (OSError, ValueError, KeyError, UnicodeError, json.JSONDecodeError) as exc:
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "artifact_mismatch",
                    "message": "Raw artifact identity validation failed.",
                },
            ) from exc
        return {
            "source": "lazarus.day",
            "source_event_id": normalized,
            "content_sha256": row["content_sha256"],
            "media_type": "text/html",
            "source_url": raw.get("lazarus_day_url"),
            "original_source_url": raw.get("original_url"),
            "content": raw["raw_detail_html"],
            "original_source": raw.get("original_source"),
        }

    @application.get(
        "/api/v1/events/{source_id}/quality", dependencies=protected
    )
    def get_quality(source_id: str) -> dict[str, Any]:
        normalized, row = event_row(source_id)
        return {
            "source_event_id": normalized,
            **_json_field(row, "quality_json", {}),
        }

    @application.get(
        "/api/v1/events/{source_id}/evidence", dependencies=protected
    )
    def get_evidence(source_id: str) -> dict[str, Any]:
        normalized, row = event_row(source_id)
        return {
            "source_event_id": normalized,
            "evidence": _json_field(row, "evidence_json", []),
            "provenance": _json_field(row, "provenance_json", {}),
        }

    return application


app = create_app()
