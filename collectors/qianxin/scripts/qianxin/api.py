from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import subprocess
import threading
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol

from fastapi import (
    Depends,
    FastAPI,
    Header,
    HTTPException,
    Query,
    Request,
    Response,
    status,
)
from fastapi.responses import FileResponse
from pydantic import BaseModel, ConfigDict, Field

from .api_store import ApiStore, StoreConflict, utc_now
from .event_adapter import (
    APT_EVENT_COLUMNS,
    SCHEMA_VERSION as APT_EVENT_SCHEMA_VERSION,
    build_apt_event_product,
)
from .core import normalize_report_publisher, normalize_title
from .model_service import (
    ModelOutputError,
    ModelUnavailableError,
    SharedModelConfig,
    SharedModelRuntime,
)
from .parse_reports import PROJECT_ROOT, sha256_file


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
RUN_ID_RE = re.compile(r"^[0-9a-f]{32}$")
TERMINAL_NATIVE_STATUSES = {"completed", "completed_with_review", "failed"}
SUCCESSFUL_ITEM_STATUSES = {"completed", "completed_with_review", "manual_review"}
PUBLISHABLE_QUALITY_STATUSES = {"ready", "ready_with_filtered_items", "needs_review"}


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
    require_api_key: bool = True
    worker_enabled: bool = True
    worker_poll_seconds: float = 0.25
    busy_retry_seconds: int = 60
    public_base_url: str = ""
    event_auto_accept: bool = False

    def __post_init__(self) -> None:
        root = Path(self.project_root).resolve()
        object.__setattr__(self, "project_root", root)
        database = (
            self.database_path or root / "data" / "state" / "api" / "qianxin-api.db"
        )
        object.__setattr__(self, "database_path", Path(database).resolve())

    @classmethod
    def from_env(cls) -> "ApiSettings":
        root = Path(os.environ.get("QIANXIN_PROJECT_ROOT", PROJECT_ROOT)).resolve()
        database_value = os.environ.get("QIANXIN_API_DB")
        return cls(
            project_root=root,
            database_path=Path(database_value).resolve() if database_value else None,
            api_key=os.environ.get("QIANXIN_API_KEY") or None,
            require_api_key=_env_bool("QIANXIN_API_REQUIRE_KEY", True),
            worker_enabled=_env_bool("QIANXIN_API_WORKER", True),
            worker_poll_seconds=float(
                os.environ.get("QIANXIN_API_POLL_SECONDS", "0.25")
            ),
            busy_retry_seconds=int(
                os.environ.get("QIANXIN_API_BUSY_RETRY_SECONDS", "60")
            ),
            public_base_url=(os.environ.get("QIANXIN_PUBLIC_BASE_URL") or "")
            .strip()
            .rstrip("/"),
            event_auto_accept=_env_bool("QIANXIN_EVENT_AUTO_ACCEPT", False),
        )

    @property
    def reports_root(self) -> Path:
        return self.project_root / "data" / "reports"

    @property
    def summaries_root(self) -> Path:
        return self.project_root / "data" / "summaries"

    @property
    def merged_root(self) -> Path:
        return self.project_root / "data" / "parsed" / "merged"

    @property
    def metadata_path(self) -> Path:
        return self.project_root / "data" / "metadata" / "qianxin-reports.jsonl"

    @property
    def wrapper_path(self) -> Path:
        return self.project_root / "scripts" / "qianxin" / "run_weekly_incremental.ps1"

    @property
    def manifest_root(self) -> Path:
        return self.project_root / "data" / "state" / "weekly-incremental-runs"

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
    ) -> RunResult:
        ...


class PowerShellPipelineRunner:
    """Runs only the fixed, reviewed incremental wrapper with a fixed argument set."""

    def __init__(self, settings: ApiSettings) -> None:
        self.settings = settings

    @staticmethod
    def _powershell_executable() -> str:
        system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
        candidate = (
            system_root / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
        )
        return str(candidate) if candidate.exists() else "powershell.exe"

    def run(
        self,
        run: Mapping[str, Any],
        on_started: Callable[[int, Path, Path], None],
    ) -> RunResult:
        invocation_id = str(run["invocation_id"])
        if not re.fullmatch(r"api-[0-9a-f]{32}", invocation_id):
            raise ValueError("invalid persisted invocation ID")

        self.settings.api_log_root.mkdir(parents=True, exist_ok=True)
        self.settings.manifest_root.mkdir(parents=True, exist_ok=True)
        log_path = self.settings.api_log_root / f"{invocation_id}.log"
        manifest_path = self.settings.manifest_root / f"{invocation_id}.json"
        if manifest_path.is_file():
            try:
                manifest = _read_json(manifest_path)
                if (
                    manifest.get("run_id") == invocation_id
                    and manifest.get("status") in TERMINAL_NATIVE_STATUSES
                ):
                    native_exit = (
                        0
                        if manifest["status"] in {"completed", "completed_with_review"}
                        else 1
                    )
                    on_started(0, log_path, manifest_path)
                    return RunResult(
                        exit_code=native_exit,
                        manifest_path=manifest_path,
                        log_path=log_path,
                    )
            except (OSError, ValueError, json.JSONDecodeError):
                pass
        argv = [
            self._powershell_executable(),
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(self.settings.wrapper_path),
            "-InvocationId",
            invocation_id,
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
        return RunResult(
            exit_code=exit_code, manifest_path=manifest_path, log_path=log_path
        )


class RunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mode: str = Field(default="incremental", pattern=r"^incremental$")


class LazarusEnrichmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    source_event_id: str = Field(min_length=1, max_length=256)
    source_url: str = Field(min_length=8, max_length=2048)
    report_title: str = Field(min_length=1, max_length=1000)
    publisher: str = Field(default="", max_length=500)
    source_sha256: str = Field(pattern=r"^[0-9a-fA-F]{64}$")
    source_content: str = Field(min_length=1, max_length=50000)


class ModelService(Protocol):
    def status(self) -> dict[str, Any]: ...

    def ensure_ready(self) -> dict[str, Any]: ...

    def enrich_lazarus(self, request: Mapping[str, Any]) -> dict[str, Any]: ...

    def close(self) -> None: ...


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("JSON artifact must contain an object")
    return value


def _relative_to_root(path: Path, root: Path) -> str:
    return path.resolve(strict=True).relative_to(root.resolve(strict=True)).as_posix()


def _resolve_project_relative(project_root: Path, value: str) -> Path:
    candidate = Path(value)
    if candidate.is_absolute():
        return candidate.resolve(strict=True)
    return (project_root / candidate).resolve(strict=True)


def _safe_indexed_path(
    project_root: Path, relative_path: str, allowed_root: Path
) -> Path:
    if not relative_path or Path(relative_path).is_absolute():
        raise ValueError("invalid indexed relative path")
    resolved = (project_root / Path(relative_path)).resolve(strict=True)
    resolved.relative_to(allowed_root.resolve(strict=True))
    return resolved


def _metadata_by_sha(settings: ApiSettings) -> dict[str, dict[str, Any]]:
    """Return canonical downloads enriched by trustworthy later observations.

    Historical download rows predate the ``report_publisher`` field.  A later
    crawl can observe the publisher from the platform table without downloading
    the same PDF again, so that observation is stored on an ``already_exists``
    row without a SHA-256.  Join it back only through the exact organization,
    normalized title and publication-date identity.  Conflicting publisher
    observations are intentionally ignored instead of guessing.
    """

    records: dict[str, dict[str, Any]] = {}
    publishers_by_identity: dict[tuple[str, str, str], set[str]] = {}
    if not settings.metadata_path.exists():
        return records
    with settings.metadata_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            try:
                row = json.loads(line)
            except (json.JSONDecodeError, UnicodeError):
                continue
            identity = (
                str(row.get("organization_id") or "").strip(),
                normalize_title(str(row.get("report_title") or "")),
                str(row.get("report_date") or "").strip(),
            )
            publisher = normalize_report_publisher(row.get("report_publisher"))
            if all(identity) and publisher:
                publishers_by_identity.setdefault(identity, set()).add(publisher)
            sha256 = str(row.get("sha256") or "").lower()
            if not SHA256_RE.fullmatch(sha256):
                continue
            if row.get("download_status") != "downloaded":
                continue
            # The first successful download is the canonical content observation.
            # Later already_exists rows are aliases, and repeated crawls must not rename
            # an existing report that happens to share its PDF bytes.
            records.setdefault(sha256, dict(row))
    for row in records.values():
        canonical_publisher = normalize_report_publisher(row.get("report_publisher"))
        if canonical_publisher:
            row["report_publisher"] = canonical_publisher
            continue
        identity = (
            str(row.get("organization_id") or "").strip(),
            normalize_title(str(row.get("report_title") or "")),
            str(row.get("report_date") or "").strip(),
        )
        observed = publishers_by_identity.get(identity, set())
        if len(observed) == 1:
            row["report_publisher"] = next(iter(observed))
    return records


def _parsed_content_hash(document: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        document.get("pages", []),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _report_product(
    settings: ApiSettings,
    summary_path: Path,
    metadata: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    summary_path = summary_path.resolve(strict=True)
    summary_path.relative_to(settings.summaries_root.resolve(strict=True))
    quality_path = (summary_path.parent / "quality.json").resolve(strict=True)
    markdown_path = summary_path.parent / "summary.md"
    summary = _read_json(summary_path)
    quality = _read_json(quality_path)

    source = summary.get("source")
    if not isinstance(source, dict):
        raise ValueError("summary source is missing")
    sha256 = str(source.get("sha256") or "").lower()
    if not SHA256_RE.fullmatch(sha256):
        raise ValueError("summary source SHA-256 is invalid")
    if summary_path.parent.name.lower() != sha256[:8]:
        raise ValueError("summary directory does not match source SHA-256")
    if str(quality.get("source_sha256") or "").lower() != sha256:
        raise ValueError("quality source SHA-256 does not match summary")

    pdf_path = _resolve_project_relative(
        settings.project_root, str(source.get("path") or "")
    )
    pdf_path.relative_to(settings.reports_root.resolve(strict=True))
    if sha256_file(pdf_path).lower() != sha256:
        raise ValueError("PDF content hash does not match summary")

    organization_directory = str(source.get("organization_directory") or "")
    merged_path = (
        settings.merged_root / organization_directory / sha256[:8] / "document.json"
    ).resolve(strict=True)
    merged_path.relative_to(settings.merged_root.resolve(strict=True))
    merged = _read_json(merged_path)
    if str(merged.get("source", {}).get("sha256") or "").lower() != sha256:
        raise ValueError("merged document source SHA-256 does not match summary")
    parsed_content_sha256 = _parsed_content_hash(merged)
    if str(quality.get("parsed_content_sha256") or "").lower() != parsed_content_sha256:
        raise ValueError("summary was not generated from the current merged document")

    metadata_row = dict(metadata.get(sha256) or {})
    if metadata_row.get("local_path"):
        try:
            metadata_pdf = _resolve_project_relative(
                settings.project_root, str(metadata_row["local_path"])
            )
            metadata_pdf.relative_to(settings.reports_root.resolve(strict=True))
            if metadata_pdf != pdf_path:
                metadata_row = {}
        except (OSError, ValueError):
            metadata_row = {}

    summary_bytes = summary_path.read_bytes()
    quality_bytes = quality_path.read_bytes()
    summary_body = (
        summary.get("summary") if isinstance(summary.get("summary"), dict) else {}
    )
    quality_status = str(quality.get("status") or "unknown")
    if quality_status not in PUBLISHABLE_QUALITY_STATUSES:
        raise ValueError("summary quality status is not publishable")
    model = summary.get("model") if isinstance(summary.get("model"), dict) else {}
    product = {
        "sha256": sha256,
        "organization_id": metadata_row.get("organization_id"),
        "organization_name": (
            metadata_row.get("organization_name")
            or organization_directory.partition("_")[2]
            or organization_directory
            or "unknown"
        ),
        "report_title": (
            summary_body.get("report_title")
            or metadata_row.get("report_title")
            or source.get("file_name")
            or "untitled"
        ),
        "report_date": source.get("report_date") or metadata_row.get("report_date"),
        "collected_at": metadata_row.get("collected_at"),
        "pdf_relpath": _relative_to_root(pdf_path, settings.project_root),
        "summary_relpath": _relative_to_root(summary_path, settings.project_root),
        "quality_relpath": _relative_to_root(quality_path, settings.project_root),
        "markdown_relpath": (
            _relative_to_root(markdown_path, settings.project_root)
            if markdown_path.is_file()
            else None
        ),
        "file_size": pdf_path.stat().st_size,
        "page_count": int(
            quality.get("page_count") or source.get("pdf_page_count") or 0
        ),
        "quality_status": quality_status,
        "review_required": quality_status != "ready",
        "model_name": model.get("name"),
        "prompt_version": summary.get("prompt_version"),
        "validator_version": quality.get("validator_version"),
        "parsed_content_sha256": parsed_content_sha256,
        "source_url": (metadata_row.get("preview_url") or metadata_row.get("pdf_url")),
        "report_publisher": metadata_row.get("report_publisher"),
    }
    metadata_digest = json.dumps(
        {
            key: product.get(key)
            for key in (
                "organization_id",
                "organization_name",
                "report_title",
                "report_date",
                "collected_at",
                "pdf_relpath",
                "source_url",
                "report_publisher",
            )
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    product["product_digest"] = hashlib.sha256(
        summary_bytes + b"\0" + quality_bytes + b"\0" + metadata_digest
    ).hexdigest()
    return product


def index_reports(
    settings: ApiSettings,
    store: ApiStore,
    run_id: str | None = None,
) -> dict[str, Any]:
    metadata = _metadata_by_sha(settings)
    indexed: set[str] = set()
    changed = 0
    errors: list[dict[str, str]] = []
    changed_sha256: list[str] = []
    if not settings.summaries_root.exists():
        return {
            "indexed": 0,
            "indexed_sha256": [],
            "changed": 0,
            "changed_sha256": [],
            "errors": [],
        }
    for summary_path in sorted(settings.summaries_root.glob("*/*/summary.json")):
        try:
            report = _report_product(settings, summary_path, metadata)
            if report["sha256"] in indexed:
                raise ValueError("duplicate full SHA-256 summary product")
            indexed.add(report["sha256"])
            if store.upsert_report(report, run_id=run_id):
                changed += 1
                changed_sha256.append(report["sha256"])
        except (
            OSError,
            ValueError,
            KeyError,
            TypeError,
            AttributeError,
            json.JSONDecodeError,
        ) as exc:
            candidate_sha = ""
            try:
                candidate_sha = str(
                    _read_json(summary_path).get("source", {}).get("sha256") or ""
                ).lower()
            except Exception:
                pass
            errors.append(
                {
                    "artifact": summary_path.parent.name,
                    "sha256": candidate_sha
                    if SHA256_RE.fullmatch(candidate_sha)
                    else "",
                    "error": str(exc),
                }
            )
    return {
        "indexed": len(indexed),
        "indexed_sha256": sorted(indexed),
        "changed": changed,
        "changed_sha256": changed_sha256,
        "errors": errors,
    }


def _manifest_result(
    path: Path, expected_run_id: str
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    manifest = _read_json(path.resolve(strict=True))
    if manifest.get("run_id") != expected_run_id:
        raise ValueError("native manifest run ID does not match API invocation")
    native_status = str(manifest.get("status") or "")
    if native_status not in TERMINAL_NATIVE_STATUSES:
        raise ValueError("native manifest is not terminal")
    download = (
        manifest.get("download") if isinstance(manifest.get("download"), dict) else {}
    )
    if (
        native_status in {"completed", "completed_with_review"}
        and download.get("status") != "success"
    ):
        raise ValueError("native download stage is not successful")
    items: list[dict[str, Any]] = []
    current_items = manifest.get("items") or []
    recovery_items = manifest.get("recovery_items") or []
    if not isinstance(current_items, list) or not isinstance(recovery_items, list):
        raise ValueError("native manifest item collections must be arrays")
    seen_sha256: set[str] = set()
    for origin, item in [("current", value) for value in current_items] + [
        ("recovery", value) for value in recovery_items
    ]:
        if not isinstance(item, dict):
            raise ValueError("native manifest contains an invalid item")
        sha256 = str(item.get("sha256") or "").lower()
        if not SHA256_RE.fullmatch(sha256):
            raise ValueError("native manifest contains an invalid SHA-256")
        if sha256 in seen_sha256:
            raise ValueError("native manifest contains a duplicate SHA-256")
        seen_sha256.add(sha256)
        item_status = str(item.get("status") or "unknown")
        if (
            native_status in {"completed", "completed_with_review"}
            and item_status not in SUCCESSFUL_ITEM_STATUSES
        ):
            raise ValueError("successful native manifest contains a non-terminal item")
        items.append(
            {
                "sha256": sha256,
                "origin": origin,
                "status": item_status,
                "organization": item.get("organization"),
                "review_required": bool(item.get("review_required"))
                or item_status in {"completed_with_review", "manual_review"},
                "error_kind": item.get("error_kind"),
                "error": item.get("error"),
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
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(
            target=self._loop, name="qianxin-api-worker", daemon=True
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
                run = self.store.claim_next_run()
            except Exception:
                # A transient store failure must not permanently kill the only worker.
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
                        native_run_id=str(run.get("invocation_id") or ""),
                        error=f"pipeline worker failed: {type(exc).__name__}",
                    )
                except Exception:
                    pass

    def _execute(self, run: Mapping[str, Any]) -> None:
        run_id = str(run["id"])
        invocation_id = str(run["invocation_id"])

        def on_started(pid: int, log_path: Path, manifest_path: Path) -> None:
            self.store.set_run_process(
                run_id,
                pid=pid,
                log_relpath=log_path.resolve()
                .relative_to(self.settings.project_root)
                .as_posix(),
                manifest_relpath=manifest_path.resolve()
                .relative_to(self.settings.project_root)
                .as_posix(),
            )

        try:
            result = self.runner.run(run, on_started)
        except Exception as exc:  # Persist process launch/runner failures as a job result.
            self.store.finish_run(
                run_id,
                status="failed",
                exit_code=None,
                native_status=None,
                native_run_id=invocation_id,
                error=f"pipeline process could not be completed: {type(exc).__name__}",
            )
            return

        if result.exit_code == 20:
            available = datetime.now(timezone.utc) + timedelta(
                seconds=self.settings.busy_retry_seconds
            )
            self.store.reschedule_run(
                run_id,
                available_at=available.isoformat().replace("+00:00", "Z"),
                error="collector lock is busy; retry scheduled",
            )
            return

        native_status: str | None = None
        items: list[dict[str, Any]] = []
        error: str | None = None
        try:
            manifest, items = _manifest_result(result.manifest_path, invocation_id)
            native_status = str(manifest["status"])
            self.store.replace_run_items(run_id, items)
        except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
            manifest = {}
            error = f"native manifest validation failed: {type(exc).__name__}"

        indexing = index_reports(self.settings, self.store, run_id=run_id)
        failed_items = sum(
            item["status"] not in SUCCESSFUL_ITEM_STATUSES for item in items
        )
        review_items = sum(bool(item["review_required"]) for item in items)
        completed_items = sum(
            item["status"] in SUCCESSFUL_ITEM_STATUSES for item in items
        )
        counts = {
            "discovered": len(items),
            "completed": completed_items,
            "review": review_items,
            "failed": failed_items,
        }

        if (
            result.exit_code == 0
            and error is None
            and native_status
            in {
                "completed",
                "completed_with_review",
            }
        ):
            final_status = (
                "completed_with_review"
                if native_status == "completed_with_review" or review_items
                else "completed"
            )
        else:
            final_status = "failed"
            if error is None:
                error = f"pipeline exited with code {result.exit_code}"
        touched_sha256 = {str(item["sha256"]) for item in items}
        indexed_sha256 = set(indexing.get("indexed_sha256") or [])
        missing_completed_products = [
            item
            for item in items
            if item["status"] in {"completed", "completed_with_review"}
            and item["sha256"] not in indexed_sha256
            and self.store.get_report(item["sha256"]) is None
        ]
        touched_artifact_errors = [
            artifact_error
            for artifact_error in indexing["errors"]
            if str(artifact_error.get("sha256") or "") in touched_sha256
        ]
        if touched_artifact_errors:
            final_status = "failed"
            error = f"{len(touched_artifact_errors)} touched report artifact(s) failed validation"
        if missing_completed_products:
            final_status = "failed"
            error = f"{len(missing_completed_products)} completed report artifact(s) are missing"
        self.store.finish_run(
            run_id,
            status=final_status,
            exit_code=result.exit_code,
            native_status=native_status,
            native_run_id=invocation_id,
            error=error,
            counts=counts,
        )


def _cursor_secret(store: ApiStore) -> bytes:
    value = store.set_meta_if_absent("cursor_secret", secrets.token_hex(32))
    return bytes.fromhex(value)


def _cursor_instance(store: ApiStore) -> str:
    return store.set_meta_if_absent("instance_id", str(uuid.uuid4()))


def _encode_cursor(store: ApiStore, after_seq: int, feed: str = "reports") -> str:
    payload = json.dumps(
        {"v": 1, "instance": _cursor_instance(store), "feed": feed, "after": after_seq},
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    signature = hmac.new(_cursor_secret(store), payload, hashlib.sha256).digest()
    payload_token = base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")
    signature_token = base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")
    return f"{payload_token}.{signature_token}"


def _decode_cursor(store: ApiStore, token: str | None, feed: str = "reports") -> int:
    if not token:
        return 0
    try:
        payload_token, signature_token = token.split(".", 1)
        payload = base64.urlsafe_b64decode(
            payload_token + "=" * (-len(payload_token) % 4)
        )
        signature = base64.urlsafe_b64decode(
            signature_token + "=" * (-len(signature_token) % 4)
        )
        expected = hmac.new(_cursor_secret(store), payload, hashlib.sha256).digest()
        if not hmac.compare_digest(signature, expected):
            raise ValueError("signature")
        value = json.loads(payload)
        if not isinstance(value, dict):
            raise ValueError("payload")
        if value != {
            "v": 1,
            "instance": _cursor_instance(store),
            "feed": feed,
            "after": value.get("after"),
        }:
            raise ValueError("scope")
        after = value["after"]
        if not isinstance(after, int) or after < 0:
            raise ValueError("position")
        return after
    except (ValueError, KeyError, TypeError, json.JSONDecodeError, UnicodeError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "code": "invalid_cursor",
                "message": "Cursor is invalid or expired.",
            },
        ) from exc


def _public_run(row: Mapping[str, Any], include_error: bool = True) -> dict[str, Any]:
    run_id = str(row["id"])
    value = {
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
            "completed": row["completed_count"],
            "review": row["review_count"],
            "failed": row["failed_count"],
        },
        "links": {
            "self": f"/api/v1/runs/{run_id}",
            "reports": f"/api/v1/runs/{run_id}/reports",
        },
    }
    if include_error and row.get("error"):
        value["error"] = {"message": str(row["error"])}
    return value


def _public_report(row: Mapping[str, Any], change: bool = False) -> dict[str, Any]:
    sha256 = str(row["sha256"])
    value: dict[str, Any] = {
        "sha256": sha256,
        "organization": {
            "id": row.get("organization_id"),
            "name": row["organization_name"],
        },
        "title": row["report_title"],
        "report_date": row.get("report_date"),
        "collected_at": row.get("collected_at"),
        "file_size": row["file_size"],
        "page_count": row["page_count"],
        "quality_status": row["quality_status"],
        "review_required": bool(row["review_required"]),
        "model": row.get("model_name"),
        "version": row["version"],
        "updated_at": row["updated_at"],
        "links": {
            "self": f"/api/v1/reports/{sha256}",
            "summary": f"/api/v1/reports/{sha256}/summary",
            "quality": f"/api/v1/reports/{sha256}/quality",
            "pdf": f"/api/v1/reports/{sha256}/pdf",
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


def _validate_report_artifact_pair(
    settings: ApiSettings,
    row: Mapping[str, Any],
    expected_sha256: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    summary_path = _safe_indexed_path(
        settings.project_root, str(row["summary_relpath"]), settings.summaries_root
    )
    quality_path = _safe_indexed_path(
        settings.project_root, str(row["quality_relpath"]), settings.summaries_root
    )
    summary = _read_json(summary_path)
    quality = _read_json(quality_path)
    if str(summary.get("source", {}).get("sha256") or "").lower() != expected_sha256:
        raise ValueError("summary identity")
    if str(quality.get("source_sha256") or "").lower() != expected_sha256:
        raise ValueError("quality identity")
    if (
        str(quality.get("parsed_content_sha256") or "").lower()
        != str(row.get("parsed_content_sha256") or "").lower()
    ):
        raise ValueError("parsed content identity")

    metadata = _metadata_by_sha(settings)
    rebuilt = _report_product(settings, summary_path, metadata)
    if rebuilt["product_digest"] != row["product_digest"]:
        raise ValueError("product digest")
    return summary, quality


def _public_event(
    settings: ApiSettings,
    row: Mapping[str, Any],
    metadata: Mapping[str, Any] | None,
    *,
    change: bool = False,
) -> dict[str, Any]:
    sha256 = str(row["sha256"])
    summary, quality = _validate_report_artifact_pair(settings, row, sha256)
    value = build_apt_event_product(
        row,
        summary,
        quality,
        metadata,
        public_base_url=settings.public_base_url,
        allow_auto_accept=settings.event_auto_accept,
    )
    if change:
        value["change"] = {
            "seq": row["change_seq"],
            "operation": row["operation"],
            "version": row["change_version"],
            "changed_at": row["changed_at"],
        }
    return value


def _normalize_sha(sha256: str) -> str:
    normalized = sha256.lower()
    if not SHA256_RE.fullmatch(normalized):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "code": "invalid_sha256",
                "message": "A full 64-character SHA-256 is required.",
            },
        )
    return normalized


def create_app(
    settings: ApiSettings | None = None,
    store: ApiStore | None = None,
    runner: PipelineRunner | None = None,
    model_service: ModelService | None = None,
) -> FastAPI:
    settings = settings or ApiSettings.from_env()
    store = store or ApiStore(settings.database_path)  # type: ignore[arg-type]
    runner = runner or PowerShellPipelineRunner(settings)
    worker = PipelineWorker(settings, store, runner)
    model_service = model_service or SharedModelRuntime(
        SharedModelConfig.from_project_root(settings.project_root)
    )

    @asynccontextmanager
    async def lifespan(application: FastAPI):
        store.initialize()
        indexing = index_reports(settings, store)
        application.state.initial_index = indexing
        if settings.worker_enabled:
            worker.start()
        try:
            yield
        finally:
            worker.stop()
            model_service.close()

    application = FastAPI(
        title="Qianxin APT Report Collector API",
        version="1.0.0",
        description=(
            "Local asynchronous API for incremental Qianxin report collection, "
            "PDF parsing, grounded draft summaries, and SHA-addressed artifacts."
        ),
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    application.state.settings = settings
    application.state.store = store
    application.state.worker = worker
    application.state.model_service = model_service

    def require_api_key(
        x_api_key: str | None = Header(default=None, alias="X-API-Key")
    ) -> None:
        expected = settings.api_key
        if settings.require_api_key and not expected:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={
                    "code": "api_key_not_configured",
                    "message": "API key is not configured.",
                },
            )
        if expected and (not x_api_key or not hmac.compare_digest(x_api_key, expected)):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
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
        checks = {
            "database": store.ping(),
            "wrapper": settings.wrapper_path.is_file(),
            "reports_root": settings.reports_root.is_dir(),
            "artifact_index": not bool(
                application.state.initial_index.get("errors", [])
            ),
        }
        ready = all(checks.values())
        if not ready:
            response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {
            "status": "ready" if ready else "not_ready",
            "checks": checks,
            "indexed_reports": store.count_reports() if checks["database"] else 0,
        }

    @application.get("/api/v1/model/status", dependencies=protected)
    def model_status() -> dict[str, Any]:
        return model_service.status()

    @application.post("/api/v1/model/ensure", dependencies=protected)
    def ensure_model() -> dict[str, Any]:
        try:
            return model_service.ensure_ready()
        except ModelUnavailableError as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={
                    "code": "model_unavailable",
                    "message": str(exc),
                },
            ) from exc

    @application.post(
        "/api/v1/model/lazarus/enrich", dependencies=protected
    )
    def enrich_lazarus(request: LazarusEnrichmentRequest) -> dict[str, Any]:
        value = request.model_dump()
        actual_sha256 = hashlib.sha256(
            request.source_content.encode("utf-8")
        ).hexdigest()
        if not hmac.compare_digest(request.source_sha256.casefold(), actual_sha256):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={
                    "code": "source_hash_mismatch",
                    "message": "source_sha256 does not match source_content.",
                },
            )
        if not request.source_url.startswith(("http://", "https://")):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={
                    "code": "invalid_source_url",
                    "message": "source_url must use HTTP or HTTPS.",
                },
            )
        try:
            return model_service.enrich_lazarus(value)
        except ModelUnavailableError as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={
                    "code": "model_unavailable",
                    "message": str(exc),
                },
            ) from exc
        except ModelOutputError as exc:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail={
                    "code": "invalid_model_output",
                    "message": str(exc),
                },
            ) from exc

    @application.post(
        "/api/v1/runs",
        status_code=status.HTTP_202_ACCEPTED,
        dependencies=protected,
    )
    def create_run(
        request: RunRequest,
        response: Response,
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    ) -> dict[str, Any]:
        if idempotency_key is not None:
            idempotency_key = idempotency_key.strip()
            if not idempotency_key or len(idempotency_key) > 128:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
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
                status_code=status.HTTP_409_CONFLICT,
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
    def list_runs(limit: int = Query(default=50, ge=1, le=200)) -> dict[str, Any]:
        return {"items": [_public_run(row) for row in store.list_runs(limit)]}

    @application.get("/api/v1/runs/{run_id}", dependencies=protected)
    def get_run(run_id: str) -> dict[str, Any]:
        if not RUN_ID_RE.fullmatch(run_id):
            raise HTTPException(status_code=404, detail={"code": "run_not_found"})
        row = store.get_run(run_id)
        if row is None:
            raise HTTPException(status_code=404, detail={"code": "run_not_found"})
        return _public_run(row)

    @application.get("/api/v1/runs/{run_id}/reports", dependencies=protected)
    def get_run_reports(run_id: str) -> dict[str, Any]:
        if not RUN_ID_RE.fullmatch(run_id) or store.get_run(run_id) is None:
            raise HTTPException(status_code=404, detail={"code": "run_not_found"})
        items = store.list_run_items(run_id)
        reports = {item["sha256"]: store.get_report(item["sha256"]) for item in items}
        return {
            "run_id": run_id,
            "items": [
                {
                    "sha256": item["sha256"],
                    "status": item["status"],
                    "review_required": bool(item["review_required"]),
                    "error_kind": item.get("error_kind"),
                    "error": (
                        "Item processing failed; inspect the local collector log."
                        if item.get("error")
                        else None
                    ),
                    "report": (
                        _public_report(reports[item["sha256"]])
                        if reports.get(item["sha256"]) is not None
                        else None
                    ),
                }
                for item in items
            ],
        }

    @application.get("/api/v1/reports", dependencies=protected)
    def list_reports(
        cursor: str | None = Query(default=None),
        limit: int = Query(default=50, ge=1, le=200),
    ) -> dict[str, Any]:
        after_seq = _decode_cursor(store, cursor)
        rows, has_more = store.list_changes(after_seq, limit)
        next_seq = int(rows[-1]["change_seq"]) if rows else after_seq
        return {
            "items": [_public_report(row, change=True) for row in rows],
            "next_cursor": _encode_cursor(store, next_seq),
            "has_more": has_more,
        }

    @application.get("/api/v1/events", dependencies=protected)
    def list_events(
        cursor: str | None = Query(default=None),
        limit: int = Query(default=50, ge=1, le=200),
    ) -> dict[str, Any]:
        after_seq = _decode_cursor(store, cursor, feed="apt_events")
        rows, has_more = store.list_changes(after_seq, limit)
        next_seq = int(rows[-1]["change_seq"]) if rows else after_seq
        metadata = _metadata_by_sha(settings)
        try:
            items = [
                _public_event(
                    settings,
                    row,
                    metadata.get(str(row["sha256"])),
                    change=True,
                )
                for row in rows
            ]
        except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "event_conversion_failed",
                    "message": "APT event conversion failed artifact validation.",
                },
            ) from exc
        return {
            "schema_version": APT_EVENT_SCHEMA_VERSION,
            "auto_accept_enabled": settings.event_auto_accept,
            "columns": list(APT_EVENT_COLUMNS),
            "items": items,
            "next_cursor": _encode_cursor(store, next_seq, feed="apt_events"),
            "has_more": has_more,
        }

    def get_report_row(sha256: str) -> tuple[str, dict[str, Any]]:
        normalized = _normalize_sha(sha256)
        row = store.get_report(normalized)
        if row is None:
            raise HTTPException(status_code=404, detail={"code": "report_not_found"})
        return normalized, row

    @application.get("/api/v1/events/{sha256}", dependencies=protected)
    def get_event(sha256: str) -> dict[str, Any]:
        normalized, row = get_report_row(sha256)
        metadata = _metadata_by_sha(settings).get(normalized)
        try:
            return _public_event(settings, row, metadata)
        except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "event_conversion_failed",
                    "message": "APT event conversion failed artifact validation.",
                },
            ) from exc

    @application.get("/api/v1/reports/{sha256}", dependencies=protected)
    def get_report(sha256: str) -> dict[str, Any]:
        _, row = get_report_row(sha256)
        return _public_report(row)

    @application.get("/api/v1/reports/{sha256}/summary", dependencies=protected)
    def get_summary(sha256: str) -> dict[str, Any]:
        normalized, row = get_report_row(sha256)
        try:
            product, _ = _validate_report_artifact_pair(settings, row, normalized)
        except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "artifact_mismatch",
                    "message": "Summary identity validation failed.",
                },
            ) from exc
        return {
            "sha256": normalized,
            "quality_status": row["quality_status"],
            "review_required": bool(row["review_required"]),
            "notice": "Machine-generated analytical draft; preserve evidence links and review before publication.",
            "product": product,
        }

    @application.get("/api/v1/reports/{sha256}/quality", dependencies=protected)
    def get_quality(sha256: str) -> dict[str, Any]:
        normalized, row = get_report_row(sha256)
        try:
            _, quality = _validate_report_artifact_pair(settings, row, normalized)
        except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "artifact_mismatch",
                    "message": "Quality identity validation failed.",
                },
            ) from exc
        return quality

    @application.get("/api/v1/reports/{sha256}/pdf", dependencies=protected)
    def get_pdf(sha256: str, request: Request) -> FileResponse:
        normalized, row = get_report_row(sha256)
        try:
            path = _safe_indexed_path(
                settings.project_root, row["pdf_relpath"], settings.reports_root
            )
            if sha256_file(path).lower() != normalized:
                raise ValueError("hash mismatch")
        except (OSError, ValueError) as exc:
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "artifact_mismatch",
                    "message": "PDF identity validation failed.",
                },
            ) from exc
        filename = f"qianxin-{normalized[:12]}.pdf"
        return FileResponse(
            path,
            media_type="application/pdf",
            filename=filename,
            headers={
                "ETag": f'"sha256-{normalized}"',
                "Cache-Control": "private, immutable",
            },
        )

    return application


# Uvicorn import target. Importing this object does not open SQLite or start a thread;
# all stateful work is deferred to the lifespan context.
app = create_app()
