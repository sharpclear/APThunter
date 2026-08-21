from __future__ import annotations

import hashlib
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Mapping

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient

from scripts.qianxin import api as api_module
from scripts.qianxin.api import (
    ApiSettings,
    PipelineWorker,
    PowerShellPipelineRunner,
    RunResult,
    _metadata_by_sha,
    create_app,
)
from scripts.qianxin.api_store import ApiStore, StoreConflict


API_KEY = "test-api-key-that-never-leaves-the-test"
AUTH = {"X-API-Key": API_KEY}


def make_project(tmp_path: Path) -> Path:
    root = tmp_path / "project"
    for relative in (
        "data/reports",
        "data/summaries",
        "data/parsed/merged",
        "data/metadata",
        "data/state/weekly-incremental-runs",
        "logs/api",
        "scripts/qianxin",
    ):
        (root / relative).mkdir(parents=True, exist_ok=True)
    (root / "scripts/qianxin/run_weekly_incremental.ps1").write_text(
        "# test placeholder; never executed\n", encoding="utf-8"
    )
    (root / "data/metadata/qianxin-reports.jsonl").write_text("", encoding="utf-8")
    return root


def make_settings(
    root: Path,
    *,
    api_key: str | None = API_KEY,
    require_api_key: bool = True,
    worker_enabled: bool = False,
    busy_retry_seconds: int = 60,
) -> ApiSettings:
    return ApiSettings(
        project_root=root,
        database_path=root / "data/state/api/test.db",
        api_key=api_key,
        require_api_key=require_api_key,
        worker_enabled=worker_enabled,
        worker_poll_seconds=0.01,
        busy_retry_seconds=busy_retry_seconds,
    )


def test_metadata_backfills_historical_publisher_from_later_observation(
    tmp_path: Path,
) -> None:
    root = make_project(tmp_path)
    settings = make_settings(root)
    sha256 = "a" * 64
    rows = [
        {
            "organization_id": "40",
            "report_title": "APT28  Attack Report",
            "report_date": "2026-08-12",
            "sha256": sha256,
            "download_status": "downloaded",
        },
        {
            "organization_id": "40",
            "report_title": "APT28 Attack Report",
            "report_date": "2026-08-12",
            "report_publisher": "Example Security",
            "download_status": "already_exists",
        },
    ]
    settings.metadata_path.write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows),
        encoding="utf-8",
    )

    assert _metadata_by_sha(settings)[sha256]["report_publisher"] == "Example Security"


def test_metadata_does_not_guess_when_publisher_observations_conflict(
    tmp_path: Path,
) -> None:
    root = make_project(tmp_path)
    settings = make_settings(root)
    sha256 = "b" * 64
    base = {
        "organization_id": "40",
        "report_title": "APT28 Attack Report",
        "report_date": "2026-08-12",
    }
    rows = [
        {**base, "sha256": sha256, "download_status": "downloaded"},
        {**base, "report_publisher": "Vendor One", "download_status": "already_exists"},
        {**base, "report_publisher": "Vendor Two", "download_status": "already_exists"},
    ]
    settings.metadata_path.write_text(
        "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8"
    )

    assert not _metadata_by_sha(settings)[sha256].get("report_publisher")


def test_metadata_ignores_placeholder_publisher_when_real_value_exists(
    tmp_path: Path,
) -> None:
    root = make_project(tmp_path)
    settings = make_settings(root)
    sha256 = "c" * 64
    base = {
        "organization_id": "40",
        "report_title": "APT28 Attack Report",
        "report_date": "2026-08-12",
    }
    rows = [
        {
            **base,
            "sha256": sha256,
            "report_publisher": "-",
            "download_status": "downloaded",
        },
        {**base, "report_publisher": "Vendor One", "download_status": "already_exists"},
    ]
    settings.metadata_path.write_text(
        "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8"
    )

    assert _metadata_by_sha(settings)[sha256]["report_publisher"] == "Vendor One"


def make_app(
    tmp_path: Path,
    *,
    api_key: str | None = API_KEY,
    require_api_key: bool = True,
    worker_enabled: bool = False,
    runner: Any = None,
    busy_retry_seconds: int = 60,
):
    root = make_project(tmp_path)
    settings = make_settings(
        root,
        api_key=api_key,
        require_api_key=require_api_key,
        worker_enabled=worker_enabled,
        busy_retry_seconds=busy_retry_seconds,
    )
    store = ApiStore(settings.database_path)
    app = create_app(settings=settings, store=store, runner=runner)
    return root, settings, store, app


def report_record(
    sha256: str,
    *,
    digest: str = "product-v1",
    pdf_relpath: str | None = None,
    summary_relpath: str | None = None,
    quality_relpath: str | None = None,
) -> dict[str, Any]:
    sha8 = sha256[:8]
    return {
        "sha256": sha256,
        "organization_id": "40",
        "organization_name": "APT28",
        "report_title": f"Report {sha8}",
        "report_date": "2026-08-12",
        "collected_at": "2026-08-12T00:00:00Z",
        "pdf_relpath": pdf_relpath or f"data/reports/{sha8}.pdf",
        "summary_relpath": summary_relpath
        or f"data/summaries/40_APT28/{sha8}/summary.json",
        "quality_relpath": quality_relpath
        or f"data/summaries/40_APT28/{sha8}/quality.json",
        "markdown_relpath": None,
        "file_size": 123,
        "page_count": 3,
        "quality_status": "ready_with_filtered_items",
        "review_required": True,
        "model_name": "fake-model",
        "prompt_version": "test-prompt",
        "validator_version": "test-validator",
        "parsed_content_sha256": "f" * 64,
        "product_digest": digest,
    }


def create_store_run(store: ApiStore, number: int = 1) -> dict[str, Any]:
    run_id = f"{number:032x}"
    row, created = store.create_run(
        run_id=run_id,
        invocation_id=f"api-{run_id}",
        idempotency_key=None,
        request={"mode": "incremental"},
    )
    assert created
    claimed = store.claim_next_run()
    assert claimed is not None
    assert claimed["id"] == row["id"]
    return claimed


class ManifestRunner:
    """Deterministic fake runner; it never creates a child process."""

    def __init__(
        self,
        root: Path,
        *,
        exit_code: int = 0,
        native_status: str = "completed",
        items: list[dict[str, Any]] | None = None,
        missing_manifest: bool = False,
        error: Exception | None = None,
    ) -> None:
        self.root = root
        self.exit_code = exit_code
        self.native_status = native_status
        self.items = items or []
        self.missing_manifest = missing_manifest
        self.error = error
        self.calls: list[Mapping[str, Any]] = []

    def run(self, run: Mapping[str, Any], on_started):
        self.calls.append(dict(run))
        if self.error is not None:
            raise self.error
        invocation_id = str(run["invocation_id"])
        manifest = (
            self.root / f"data/state/weekly-incremental-runs/{invocation_id}.json"
        )
        log = self.root / f"logs/api/{invocation_id}.log"
        log.write_text("fake runner\n", encoding="utf-8")
        on_started(4242, log, manifest)
        if not self.missing_manifest:
            manifest.write_text(
                json.dumps(
                    {
                        "run_id": invocation_id,
                        "status": self.native_status,
                        "download": {
                            "status": (
                                "success"
                                if self.native_status
                                in {"completed", "completed_with_review"}
                                else "failed"
                            )
                        },
                        "items": self.items,
                    }
                ),
                encoding="utf-8",
            )
        return RunResult(self.exit_code, manifest, log)


class RecoveryManifestRunner(ManifestRunner):
    def run(self, run: Mapping[str, Any], on_started):
        result = super().run(run, on_started)
        manifest = json.loads(result.manifest_path.read_text(encoding="utf-8"))
        manifest["recovery_items"] = [
            {
                "sha256": "d" * 64,
                "status": "completed_with_review",
                "organization": "40_APT28",
                "review_required": True,
            }
        ]
        result.manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        return result


def test_health_is_public_but_every_api_surface_requires_key(tmp_path):
    _, _, _, app = make_app(tmp_path)
    protected_requests = [
        ("get", "/readyz", None),
        ("get", "/api/v1/model/status", None),
        ("post", "/api/v1/model/ensure", None),
        ("post", "/api/v1/model/lazarus/enrich", {}),
        ("get", "/api/v1/runs", None),
        ("post", "/api/v1/runs", {"mode": "incremental"}),
        ("get", "/api/v1/reports", None),
        ("get", "/api/v1/events", None),
        ("get", f"/api/v1/events/{'a' * 64}", None),
        ("get", f"/api/v1/reports/{'a' * 64}", None),
        ("get", f"/api/v1/reports/{'a' * 64}/summary", None),
        ("get", f"/api/v1/reports/{'a' * 64}/quality", None),
        ("get", f"/api/v1/reports/{'a' * 64}/pdf", None),
    ]
    with TestClient(app) as client:
        assert client.get("/healthz").json() == {"status": "ok"}
        for method, path, body in protected_requests:
            response = client.request(method, path, json=body)
            assert response.status_code == 401, path
            assert API_KEY not in response.text
            wrong = client.request(
                method, path, json=body, headers={"X-API-Key": "wrong"}
            )
            assert wrong.status_code == 401, path
            assert API_KEY not in wrong.text


def test_lazarus_model_endpoint_checks_source_hash(tmp_path):
    root = make_project(tmp_path)
    settings = make_settings(root)
    store = ApiStore(settings.database_path)

    class FakeModelService:
        closed = False

        def status(self):
            return {"enabled": True, "running": True, "owned_by_api": True}

        def ensure_ready(self):
            return self.status()

        def enrich_lazarus(self, request):
            return {
                "source_event_id": request["source_event_id"],
                "source_sha256": request["source_sha256"],
                "title_zh": "Kimsuky开展钓鱼活动",
            }

        def close(self):
            self.closed = True

    model = FakeModelService()
    app = create_app(
        settings=settings,
        store=store,
        model_service=model,
    )
    source = "Kimsuky launched a phishing campaign."
    payload = {
        "source_event_id": "fixture-1",
        "source_url": "https://lazarus.day/reports/fixture-1/",
        "report_title": "Fixture report",
        "publisher": "Example Research",
        "source_sha256": hashlib.sha256(source.encode("utf-8")).hexdigest(),
        "source_content": source,
    }
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/model/lazarus/enrich", headers=AUTH, json=payload
        )
        assert response.status_code == 200
        assert response.json()["source_event_id"] == "fixture-1"

        payload["source_sha256"] = "0" * 64
        mismatch = client.post(
            "/api/v1/model/lazarus/enrich", headers=AUTH, json=payload
        )
        assert mismatch.status_code == 422
        assert mismatch.json()["detail"]["code"] == "source_hash_mismatch"
    assert model.closed is True


def test_required_but_unconfigured_api_key_fails_closed(tmp_path):
    _, _, _, app = make_app(tmp_path, api_key=None, require_api_key=True)
    with TestClient(app) as client:
        assert client.get("/healthz").status_code == 200
        response = client.get("/readyz")
    assert response.status_code == 503
    assert response.json()["detail"]["code"] == "api_key_not_configured"


def test_ready_and_run_validation_idempotency_and_active_conflict(tmp_path):
    _, _, _, app = make_app(tmp_path)
    with TestClient(app) as client:
        ready = client.get("/readyz", headers=AUTH)
        assert ready.status_code == 200
        assert ready.json()["status"] == "ready"

        invalid = client.post(
            "/api/v1/runs", headers=AUTH, json={"mode": "full", "path": "evil"}
        )
        assert invalid.status_code == 422

        first = client.post(
            "/api/v1/runs",
            headers={**AUTH, "Idempotency-Key": "weekly-2026-08-16"},
            json={"mode": "incremental"},
        )
        assert first.status_code == 202
        assert first.headers["Idempotent-Replay"] == "false"
        run_id = first.json()["id"]
        assert first.headers["Location"] == f"/api/v1/runs/{run_id}"

        replay = client.post(
            "/api/v1/runs",
            headers={**AUTH, "Idempotency-Key": "weekly-2026-08-16"},
            json={"mode": "incremental"},
        )
        assert replay.status_code == 202
        assert replay.headers["Idempotent-Replay"] == "true"
        assert replay.json()["id"] == run_id

        conflict = client.post(
            "/api/v1/runs",
            headers={**AUTH, "Idempotency-Key": "a-different-job"},
            json={"mode": "incremental"},
        )
        assert conflict.status_code == 409
        assert conflict.json()["detail"]["run_id"] == run_id

        assert client.get(f"/api/v1/runs/{run_id}", headers=AUTH).status_code == 200
        assert client.get("/api/v1/runs/not-a-run-id", headers=AUTH).status_code == 404


def test_store_allows_only_one_active_run_under_thread_concurrency(tmp_path):
    root = make_project(tmp_path)
    store = ApiStore(root / "data/state/api/concurrent.db")
    store.initialize()
    barrier = threading.Barrier(8)

    def attempt(number: int) -> str:
        run_id = f"{number:032x}"
        barrier.wait()
        try:
            _, created = store.create_run(
                run_id=run_id,
                invocation_id=f"api-{run_id}",
                idempotency_key=f"request-{number}",
                request={"mode": "incremental"},
            )
            return "created" if created else "replayed"
        except StoreConflict:
            return "conflict"

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(attempt, range(1, 9)))
    assert results.count("created") == 1
    assert results.count("conflict") == 7
    assert len(store.list_runs()) == 1


def test_report_cursor_is_stable_across_paging_updates_and_restart(tmp_path):
    root, settings, store, app = make_app(tmp_path)
    sha1, sha2, sha3 = ("1" * 64, "2" * 64, "3" * 64)
    with TestClient(app) as client:
        store.upsert_report(report_record(sha1))
        store.upsert_report(report_record(sha2))

        page1 = client.get("/api/v1/reports?limit=1", headers=AUTH).json()
        assert [item["sha256"] for item in page1["items"]] == [sha1]
        assert page1["has_more"] is True

        # An insert between pages is ordered by the durable change sequence, not by
        # an unstable timestamp or OFFSET window.
        store.upsert_report(report_record(sha3))
        page2 = client.get(
            "/api/v1/reports",
            headers=AUTH,
            params={"limit": 2, "cursor": page1["next_cursor"]},
        ).json()
        assert [item["sha256"] for item in page2["items"]] == [sha2, sha3]
        assert not ({sha1} & {item["sha256"] for item in page2["items"]})

        # Updating a product is an explicit new feed change with a higher version.
        assert store.upsert_report(report_record(sha1, digest="product-v2"))
        update_page = client.get(
            "/api/v1/reports",
            headers=AUTH,
            params={"cursor": page2["next_cursor"]},
        ).json()
        assert [(item["sha256"], item["version"]) for item in update_page["items"]] == [
            (sha1, 2)
        ]
        restart_cursor = update_page["next_cursor"]

        tampered = (
            restart_cursor[:-5]
            + ("A" if restart_cursor[-5] != "A" else "B")
            + restart_cursor[-4:]
        )
        rejected = client.get(
            "/api/v1/reports", headers=AUTH, params={"cursor": tampered}
        )
        assert rejected.status_code == 400
        assert rejected.json()["detail"]["code"] == "invalid_cursor"

    # Cursor HMAC key and instance ID live in SQLite, so a normal API restart does
    # not invalidate a consumer's last acknowledged cursor.
    restarted_store = ApiStore(settings.database_path)
    restarted = create_app(settings=settings, store=restarted_store)
    with TestClient(restarted) as client:
        response = client.get(
            "/api/v1/reports", headers=AUTH, params={"cursor": restart_cursor}
        )
        assert response.status_code == 200
        assert response.json()["items"] == []


def test_apt_event_feed_has_separate_cursor_and_table_contract(tmp_path, monkeypatch):
    _, _, store, app = make_app(tmp_path)
    sha1, sha2 = "1" * 64, "2" * 64

    def fake_public_event(_settings, row, _metadata, *, change=False):
        value = {
            "source": "qianxin",
            "source_event_id": row["sha256"],
            "version": row["version"],
            "apt_event": {column: None for column in api_module.APT_EVENT_COLUMNS},
        }
        if change:
            value["change"] = {"seq": row["change_seq"]}
        return value

    monkeypatch.setattr(api_module, "_public_event", fake_public_event)
    with TestClient(app) as client:
        store.upsert_report(report_record(sha1))
        store.upsert_report(report_record(sha2))
        report_page = client.get("/api/v1/reports?limit=1", headers=AUTH).json()

        first = client.get("/api/v1/events?limit=1", headers=AUTH)
        assert first.status_code == 200
        payload = first.json()
        assert payload["schema_version"] == api_module.APT_EVENT_SCHEMA_VERSION
        assert payload["auto_accept_enabled"] is False
        assert payload["columns"] == list(api_module.APT_EVENT_COLUMNS)
        assert payload["items"][0]["source_event_id"] == sha1
        assert payload["has_more"] is True

        wrong_scope = client.get(
            "/api/v1/events",
            headers=AUTH,
            params={"cursor": report_page["next_cursor"]},
        )
        assert wrong_scope.status_code == 400

        second = client.get(
            "/api/v1/events",
            headers=AUTH,
            params={"cursor": payload["next_cursor"]},
        )
        assert second.status_code == 200
        assert [item["source_event_id"] for item in second.json()["items"]] == [sha2]

        detail = client.get(f"/api/v1/events/{sha1}", headers=AUTH)
        assert detail.status_code == 200
        assert detail.json()["source_event_id"] == sha1


def test_full_sha_pdf_lookup_and_path_traversal_protection(tmp_path):
    root, _, store, app = make_app(tmp_path)
    pdf_bytes = b"%PDF-1.4\n% harmless test bytes\n"
    sha256 = hashlib.sha256(pdf_bytes).hexdigest()
    pdf_path = root / f"data/reports/{sha256[:8]}.pdf"
    pdf_path.write_bytes(pdf_bytes)

    escaped_bytes = b"%PDF-1.4\noutside the report root\n"
    escaped_sha = hashlib.sha256(escaped_bytes).hexdigest()
    escaped = root.parent / "escaped.pdf"
    escaped.write_bytes(escaped_bytes)

    with TestClient(app) as client:
        store.upsert_report(report_record(sha256))
        store.upsert_report(
            report_record(escaped_sha, pdf_relpath="../escaped.pdf", digest="escaped")
        )

        valid = client.get(f"/api/v1/reports/{sha256.upper()}/pdf", headers=AUTH)
        assert valid.status_code == 200
        assert valid.content == pdf_bytes
        assert valid.headers["content-type"].startswith("application/pdf")
        assert sha256 in valid.headers["etag"]
        assert str(root) not in valid.headers.get("content-disposition", "")

        assert client.get("/api/v1/reports/deadbeef", headers=AUTH).status_code == 422
        assert (
            client.get(f"/api/v1/reports/{'g' * 64}", headers=AUTH).status_code == 422
        )
        assert (
            client.get(f"/api/v1/reports/{'a' * 64}", headers=AUTH).status_code == 404
        )

        traversal = client.get(f"/api/v1/reports/{escaped_sha}/pdf", headers=AUTH)
        assert traversal.status_code == 409
        assert traversal.json()["detail"]["code"] == "artifact_mismatch"
        assert str(escaped) not in traversal.text


def test_symlink_or_junction_cannot_escape_report_root(tmp_path):
    root, _, store, app = make_app(tmp_path)
    outside_bytes = b"%PDF-1.4\nsymlink escape\n"
    sha256 = hashlib.sha256(outside_bytes).hexdigest()
    outside = root.parent / "outside-target.pdf"
    outside.write_bytes(outside_bytes)
    link = root / "data/reports/linked.pdf"
    try:
        link.symlink_to(outside)
    except OSError as exc:
        pytest.skip(f"test account cannot create symlinks: {exc}")

    with TestClient(app) as client:
        store.upsert_report(
            report_record(sha256, pdf_relpath="data/reports/linked.pdf")
        )
        response = client.get(f"/api/v1/reports/{sha256}/pdf", headers=AUTH)
    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "artifact_mismatch"


def test_summary_and_quality_identity_are_revalidated_on_every_read(tmp_path):
    root, _, store, app = make_app(tmp_path)
    sha256 = "4" * 64
    product_dir = root / f"data/summaries/40_APT28/{sha256[:8]}"
    product_dir.mkdir(parents=True)
    summary = product_dir / "summary.json"
    quality = product_dir / "quality.json"
    summary.write_text(json.dumps({"source": {"sha256": "5" * 64}}), encoding="utf-8")
    quality.write_text(json.dumps({"source_sha256": "5" * 64}), encoding="utf-8")

    with TestClient(app) as client:
        store.upsert_report(report_record(sha256))
        summary_response = client.get(f"/api/v1/reports/{sha256}/summary", headers=AUTH)
        quality_response = client.get(f"/api/v1/reports/{sha256}/quality", headers=AUTH)
    assert summary_response.status_code == 409
    assert summary_response.json()["detail"]["code"] == "artifact_mismatch"
    assert quality_response.status_code == 409
    assert quality_response.json()["detail"]["code"] == "artifact_mismatch"
    assert str(root) not in summary_response.text + quality_response.text


@pytest.mark.parametrize(
    ("exit_code", "native_status", "items", "expected", "expected_counts"),
    [
        (0, "completed", [], "completed", (0, 0, 0, 0)),
        (1, "failed", [], "failed", (0, 0, 0, 0)),
        (
            0,
            "completed_with_review",
            [
                {
                    "sha256": "a" * 64,
                    "status": "completed_with_review",
                    "review_required": True,
                }
            ],
            "completed_with_review",
            (1, 1, 1, 0),
        ),
    ],
)
def test_worker_maps_manifest_and_exit_code_without_real_process(
    tmp_path, exit_code, native_status, items, expected, expected_counts
):
    root = make_project(tmp_path)
    settings = make_settings(root)
    store = ApiStore(settings.database_path)
    store.initialize()
    run = create_store_run(store)
    runner = ManifestRunner(
        root, exit_code=exit_code, native_status=native_status, items=items
    )

    for item in items:
        store.upsert_report(report_record(item["sha256"]), run_id=run["id"])

    PipelineWorker(settings, store, runner)._execute(run)

    result = store.get_run(run["id"])
    assert result is not None
    assert result["status"] == expected
    assert result["exit_code"] == exit_code
    assert (
        result["discovered_count"],
        result["completed_count"],
        result["review_count"],
        result["failed_count"],
    ) == expected_counts
    assert len(runner.calls) == 1


def test_worker_includes_recovered_items_in_api_run_result(tmp_path):
    root = make_project(tmp_path)
    settings = make_settings(root)
    store = ApiStore(settings.database_path)
    store.initialize()
    run = create_store_run(store)
    store.upsert_report(report_record("d" * 64), run_id=run["id"])

    PipelineWorker(settings, store, RecoveryManifestRunner(root))._execute(run)

    result = store.get_run(run["id"])
    assert result is not None
    assert result["status"] == "completed_with_review"
    assert result["discovered_count"] == 1
    assert result["review_count"] == 1
    items = store.list_run_items(run["id"])
    assert items[0]["sha256"] == "d" * 64
    assert items[0]["origin"] == "recovery"


def test_worker_reschedules_native_lock_conflict(tmp_path):
    root = make_project(tmp_path)
    settings = make_settings(root, busy_retry_seconds=5)
    store = ApiStore(settings.database_path)
    store.initialize()
    run = create_store_run(store)
    runner = ManifestRunner(root, exit_code=20, missing_manifest=True)

    PipelineWorker(settings, store, runner)._execute(run)

    result = store.get_run(run["id"])
    assert result is not None
    assert result["status"] == "queued"
    assert result["exit_code"] == 20
    assert result["attempts"] == 1
    assert "retry" in result["error"]


@pytest.mark.parametrize(
    ("runner", "expected_fragment"),
    [
        ("exception", "RuntimeError"),
        ("missing_manifest", "manifest validation failed"),
    ],
)
def test_worker_persists_runner_and_manifest_failures(
    tmp_path, runner, expected_fragment
):
    root = make_project(tmp_path)
    settings = make_settings(root)
    store = ApiStore(settings.database_path)
    store.initialize()
    run = create_store_run(store)
    fake = (
        ManifestRunner(root, error=RuntimeError("sensitive subprocess detail"))
        if runner == "exception"
        else ManifestRunner(root, exit_code=0, missing_manifest=True)
    )

    PipelineWorker(settings, store, fake)._execute(run)

    result = store.get_run(run["id"])
    assert result is not None
    assert result["status"] == "failed"
    assert expected_fragment in result["error"]
    assert "sensitive subprocess detail" not in result["error"]


def test_store_requeues_running_job_after_api_restart(tmp_path):
    root = make_project(tmp_path)
    database = root / "data/state/api/recovery.db"
    store = ApiStore(database)
    store.initialize()
    run = create_store_run(store)
    store.set_run_process(
        run["id"],
        pid=999999,
        log_relpath="logs/api/test.log",
        manifest_relpath="data/state/weekly-incremental-runs/test.json",
    )

    restarted = ApiStore(database)
    restarted.initialize()
    recovered = restarted.get_run(run["id"])
    assert recovered is not None
    assert recovered["status"] == "queued"
    assert recovered["pid"] is None
    assert recovered["attempts"] == 1
    assert "restarted" in recovered["error"].lower()


def test_background_worker_integration_uses_fake_runner(tmp_path):
    root = make_project(tmp_path)
    runner = ManifestRunner(root)
    settings = make_settings(root, worker_enabled=True)
    store = ApiStore(settings.database_path)
    app = create_app(settings=settings, store=store, runner=runner)

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/runs", headers=AUTH, json={"mode": "incremental"}
        )
        assert response.status_code == 202
        run_id = response.json()["id"]
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            current = client.get(f"/api/v1/runs/{run_id}", headers=AUTH).json()
            if current["status"] in {"completed", "failed"}:
                break
            time.sleep(0.01)
        assert current["status"] == "completed"
    assert len(runner.calls) == 1


def test_powershell_adapter_uses_fixed_argv_and_never_shell_true(tmp_path, monkeypatch):
    root = make_project(tmp_path)
    settings = make_settings(root)
    captured: dict[str, Any] = {}

    class FakeProcess:
        pid = 12345

        def __init__(self, argv, **kwargs):
            captured["argv"] = argv
            captured["kwargs"] = kwargs

        def wait(self):
            return 0

    monkeypatch.setattr(api_module.subprocess, "Popen", FakeProcess)
    runner = PowerShellPipelineRunner(settings)
    started: list[tuple[int, Path, Path]] = []
    invocation_id = "api-" + "b" * 32
    result = runner.run(
        {
            "invocation_id": invocation_id,
            "request_json": json.dumps(
                {"path": "..\\outside", "command": "Remove-Item -Recurse C:\\"}
            ),
        },
        lambda pid, log, manifest: started.append((pid, log, manifest)),
    )

    argv = captured["argv"]
    assert isinstance(argv, list)
    assert argv[-4:] == [
        "-File",
        str(settings.wrapper_path),
        "-InvocationId",
        invocation_id,
    ]
    assert captured["kwargs"]["shell"] is False
    assert captured["kwargs"]["cwd"] == str(root)
    assert "outside" not in " ".join(argv)
    assert result.exit_code == 0
    assert started and started[0][0] == 12345


def test_powershell_adapter_harvests_terminal_manifest_after_restart(
    tmp_path, monkeypatch
):
    root = make_project(tmp_path)
    settings = make_settings(root)
    invocation_id = "api-" + "c" * 32
    manifest = settings.manifest_root / f"{invocation_id}.json"
    manifest.write_text(
        json.dumps(
            {
                "run_id": invocation_id,
                "status": "completed_with_review",
                "download": {"status": "success"},
                "items": [],
            }
        ),
        encoding="utf-8",
    )

    def fail_if_spawned(*args, **kwargs):
        raise AssertionError("a terminal native manifest must be harvested, not rerun")

    monkeypatch.setattr(api_module.subprocess, "Popen", fail_if_spawned)
    started: list[tuple[int, Path, Path]] = []
    result = PowerShellPipelineRunner(settings).run(
        {"invocation_id": invocation_id},
        lambda pid, log, native_manifest: started.append((pid, log, native_manifest)),
    )

    assert result.exit_code == 0
    assert result.manifest_path == manifest
    assert started[0][0] == 0
