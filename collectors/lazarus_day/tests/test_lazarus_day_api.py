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

from scripts.lazarus_day import api as api_module
from scripts.lazarus_day.api import (
    ApiSettings,
    FixedCollectorRunner,
    PipelineWorker,
    RunResult,
    create_app,
    index_events,
)
from scripts.lazarus_day.api_store import ApiStore, StoreConflict, utc_now
from scripts.lazarus_day.models import CollectorLockError
from scripts.lazarus_day.storage import exclusive_collector_lock


API_KEY = "test-api-key"
AUTH = {"X-API-Key": API_KEY}
SOURCE_ID = "stable-source-report-AbC12"


def make_project(tmp_path: Path) -> Path:
    root = tmp_path / "project"
    for relative in (
        "data/events/raw/2026-08-13",
        "data/events/review",
        "data/events/state/api",
        "data/reference",
        "docs",
        "logs/api",
        "scripts/lazarus_day",
    ):
        (root / relative).mkdir(parents=True, exist_ok=True)
    (root / "scripts/collect_lazarus_day.py").write_text(
        "# fixed collector placeholder\n", encoding="utf-8"
    )
    (root / "data/reference/apt_organizations.csv").write_text(
        "id,name,aliases\n53,Kimsuky,APT43\n",
        encoding="utf-8",
        newline="\n",
    )
    (root / "data/reference/apt_events.csv").write_text(
        "id,event_date,title,description,threat_type,organization_id,"
        "releasing_product,link\n",
        encoding="utf-8",
        newline="\n",
    )
    (root / "docs/APT事件数据采集及导入格式规范.md").write_text(
        "test spec\n", encoding="utf-8"
    )
    write_raw(root)
    return root


def write_raw(root: Path, *, source_id: str = SOURCE_ID) -> Path:
    html = "<html><h1>Stable source report</h1></html>"
    row = {
        "source_record_id": source_id,
        "lazarus_day_url": f"https://lazarus.day/reports/{source_id}/",
        "original_url": "https://research.example/stable-report",
        "raw_title": "Stable report",
        "raw_summary": "Kimsuky delivered a backdoor.",
        "raw_tags": ["Backdoor"],
        "raw_related_actors": ["Kimsuky"],
        "publisher": "Research Example",
        "published_date": "2026-08-13",
        "date_precision": "day",
        "content_sha256": hashlib.sha256(html.encode()).hexdigest(),
        "fetched_at": "2026-08-13T00:00:00Z",
        "parse_warnings": [],
        "raw_detail_html": html,
        "original_source": None,
        "event_key": "e" * 64,
        "match_status": "matched",
        "dedup_status": "unique",
    }
    path = (
        root
        / "data/events/raw/2026-08-13/lazarus-day.events.raw.jsonl"
    )
    path.write_text(json.dumps(row) + "\n", encoding="utf-8", newline="\n")
    return path


def make_settings(
    root: Path,
    *,
    api_key: str | None = API_KEY,
    worker_enabled: bool = False,
    lease_seconds: float = 2.0,
) -> ApiSettings:
    return ApiSettings(
        project_root=root,
        database_path=root / "data/events/state/api/test.db",
        api_key=api_key,
        worker_enabled=worker_enabled,
        worker_poll_seconds=0.01,
        busy_retry_seconds=1,
        worker_lease_seconds=lease_seconds,
        python_executable="python-test",
    )


def make_app(tmp_path: Path, **kwargs):
    root = make_project(tmp_path)
    settings = make_settings(root, **kwargs)
    store = ApiStore(settings.database_path)
    app = create_app(settings=settings, store=store)
    return root, settings, store, app


def event_record(source_id: str, digest: str = "digest-v1") -> dict[str, Any]:
    return {
        "source_event_id": source_id,
        "source": "lazarus.day",
        "source_record_id": source_id,
        "source_url": f"https://lazarus.day/reports/{source_id}/",
        "original_url": "https://research.example/report",
        "content_sha256": "a" * 64,
        "product_digest": digest,
        "title": "Kimsuky开展恶意软件投递活动",
        "description": "公开报告披露了Kimsuky投递后门的活动。",
        "event_time": "2026-08-13",
        "report_time": "2026-08-13",
        "collected_at": "2026-08-13T00:00:00Z",
        "quality_status": "accepted",
        "review_required": False,
        "organization_id": "53",
        "organization_name": "Kimsuky",
        "threat_type": "恶意软件",
        "releasing_product": "Research Example",
        "primary_link": "https://research.example/report",
        "structured": {"variants": []},
        "evidence": [],
        "provenance": {},
        "quality": {"status": "accepted"},
        "raw_relpath": "data/events/raw/2026-08-13/lazarus-day.events.raw.jsonl",
        "raw_line": 1,
        "raw_line_sha256": "b" * 64,
    }


def create_store_run(store: ApiStore, number: int = 1) -> dict[str, Any]:
    run_id = f"{number:032x}"
    store.create_run(
        run_id=run_id,
        invocation_id=f"api-{run_id}",
        idempotency_key=None,
        request={"mode": "incremental"},
    )
    claimed = store.claim_next_run("test-worker", lease_seconds=10)
    assert claimed is not None
    return claimed


class FakeRunner:
    def __init__(
        self,
        root: Path,
        *,
        exit_code: int = 0,
        native_status: str = "completed",
        items: list[dict[str, Any]] | None = None,
        recovery_items: list[dict[str, Any]] | None = None,
        missing_manifest: bool = False,
        error: Exception | None = None,
        delay: float = 0,
    ) -> None:
        self.root = root
        self.exit_code = exit_code
        self.native_status = native_status
        self.items = items or []
        self.recovery_items = recovery_items or []
        self.missing_manifest = missing_manifest
        self.error = error
        self.delay = delay
        self.calls: list[dict[str, Any]] = []

    def run(self, run: Mapping[str, Any], on_started):
        self.calls.append(dict(run))
        if self.error:
            raise self.error
        invocation = str(run["invocation_id"])
        out = self.root / f"data/events/api-runs/{invocation}/reports"
        out.mkdir(parents=True, exist_ok=True)
        manifest = out / f"lazarus-day-run-{invocation}.json"
        log = self.root / f"logs/api/{invocation}.log"
        log.write_text("fake\n", encoding="utf-8")
        on_started(4242, log, manifest)
        if self.delay:
            time.sleep(self.delay)
        if not self.missing_manifest:
            manifest.write_text(
                json.dumps(
                    {
                        "invocation_id": invocation,
                        "status": self.native_status,
                        "items": self.items,
                        "recovery_items": self.recovery_items,
                    }
                ),
                encoding="utf-8",
            )
        return RunResult(self.exit_code, manifest, log)


def test_authentication_and_fail_closed(tmp_path):
    _, _, _, app = make_app(tmp_path)
    protected = [
        ("get", "/readyz", None),
        ("get", "/api/v1/runs", None),
        ("post", "/api/v1/runs", {"mode": "incremental"}),
        ("get", "/api/v1/events", None),
        ("get", f"/api/v1/events/{SOURCE_ID}", None),
        ("get", f"/api/v1/events/{SOURCE_ID}/raw", None),
        ("get", f"/api/v1/events/{SOURCE_ID}/quality", None),
        ("get", f"/api/v1/events/{SOURCE_ID}/evidence", None),
    ]
    with TestClient(app) as client:
        assert client.get("/healthz").json() == {"status": "ok"}
        ready = client.get("/readyz", headers=AUTH)
        assert ready.status_code == 200
        assert ready.json()["checks"]["database"] is True
        for method, path, body in protected:
            assert client.request(method, path, json=body).status_code == 401
            wrong = client.request(
                method, path, json=body, headers={"X-API-Key": "wrong"}
            )
            assert wrong.status_code == 401
            assert str(tmp_path) not in wrong.text

    _, _, _, closed = make_app(tmp_path / "closed", api_key=None)
    with TestClient(closed) as client:
        assert client.get("/healthz").status_code == 200
        response = client.get("/readyz")
        assert response.status_code == 503
        assert response.json()["detail"]["code"] == "api_key_not_configured"


def test_post_is_fast_idempotent_and_conflicts(tmp_path):
    root = make_project(tmp_path)
    settings = make_settings(root)
    store = ApiStore(settings.database_path)
    app = create_app(
        settings=settings,
        store=store,
        runner=FakeRunner(root, delay=1),
    )
    with TestClient(app) as client:
        invalid = client.post(
            "/api/v1/runs", headers=AUTH, json={"mode": "full", "path": "x"}
        )
        assert invalid.status_code == 422
        started = time.monotonic()
        first = client.post(
            "/api/v1/runs",
            headers={**AUTH, "Idempotency-Key": "weekly-1"},
            json={"mode": "incremental"},
        )
        assert time.monotonic() - started < 0.5
        assert first.status_code == 202
        assert first.headers["Idempotent-Replay"] == "false"
        run_id = first.json()["id"]
        replay = client.post(
            "/api/v1/runs",
            headers={**AUTH, "Idempotency-Key": "weekly-1"},
            json={"mode": "incremental"},
        )
        assert replay.json()["id"] == run_id
        assert replay.headers["Idempotent-Replay"] == "true"
        conflict = client.post(
            "/api/v1/runs",
            headers={**AUTH, "Idempotency-Key": "weekly-2"},
            json={"mode": "incremental"},
        )
        assert conflict.status_code == 409
        assert conflict.json()["detail"]["run_id"] == run_id


def test_store_concurrency_and_shared_claim(tmp_path):
    root = make_project(tmp_path)
    database = root / "data/events/state/api/concurrent.db"
    store = ApiStore(database)
    store.initialize()
    barrier = threading.Barrier(8)

    def create(number: int) -> str:
        barrier.wait()
        run_id = f"{number:032x}"
        try:
            store.create_run(
                run_id=run_id,
                invocation_id=f"api-{run_id}",
                idempotency_key=f"key-{number}",
                request={"mode": "incremental"},
            )
            return "created"
        except StoreConflict:
            return "conflict"

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(create, range(1, 9)))
    assert results.count("created") == 1
    assert results.count("conflict") == 7

    first = ApiStore(database)
    second = ApiStore(database)
    claimed = [
        result
        for result in (
            first.claim_next_run("app-1", lease_seconds=10),
            second.claim_next_run("app-2", lease_seconds=10),
        )
        if result is not None
    ]
    assert len(claimed) == 1


def test_two_app_instances_share_one_durable_claim(tmp_path):
    root = make_project(tmp_path)
    database = root / "data/events/state/api/shared-app.db"
    settings = ApiSettings(
        project_root=root,
        database_path=database,
        api_key=API_KEY,
        worker_enabled=True,
        worker_poll_seconds=0.01,
        worker_lease_seconds=2,
        python_executable="python-test",
    )
    first_runner = FakeRunner(root, delay=0.1)
    second_runner = FakeRunner(root, delay=0.1)
    first_app = create_app(
        settings=settings, store=ApiStore(database), runner=first_runner
    )
    second_app = create_app(
        settings=settings, store=ApiStore(database), runner=second_runner
    )
    with TestClient(first_app) as first, TestClient(second_app) as second:
        response = first.post(
            "/api/v1/runs", headers=AUTH, json={"mode": "incremental"}
        )
        assert response.status_code == 202
        run_id = response.json()["id"]
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            current = second.get(
                f"/api/v1/runs/{run_id}", headers=AUTH
            ).json()
            if current["status"] in {"completed", "failed"}:
                break
            time.sleep(0.01)
        assert current["status"] == "completed"
    assert len(first_runner.calls) + len(second_runner.calls) == 1


def test_expired_worker_lease_is_recovered(tmp_path):
    root = make_project(tmp_path)
    store = ApiStore(root / "data/events/state/api/recover.db")
    store.initialize()
    run_id = "1" * 32
    store.create_run(
        run_id=run_id,
        invocation_id=f"api-{run_id}",
        idempotency_key=None,
        request={"mode": "incremental"},
    )
    first = store.claim_next_run("dead-worker", lease_seconds=0.01)
    assert first is not None
    time.sleep(0.03)
    recovered = store.claim_next_run("new-worker", lease_seconds=10)
    assert recovered is not None
    assert recovered["id"] == run_id
    assert recovered["attempts"] == 2


def test_cursor_paging_tampering_and_restart(tmp_path):
    root, settings, store, app = make_app(tmp_path)
    one, two, three = "one-id", "two-id", "three-id"
    with TestClient(app) as client:
        baseline = client.get("/api/v1/events", headers=AUTH).json()
        baseline_cursor = baseline["next_cursor"]
        store.upsert_event(event_record(one))
        store.upsert_event(event_record(two))
        page1 = client.get(
            "/api/v1/events",
            headers=AUTH,
            params={"limit": 1, "cursor": baseline_cursor},
        ).json()
        assert [x["source_event_id"] for x in page1["items"]] == [one]
        store.upsert_event(event_record(three))
        page2 = client.get(
            "/api/v1/events",
            headers=AUTH,
            params={"limit": 2, "cursor": page1["next_cursor"]},
        ).json()
        assert [x["source_event_id"] for x in page2["items"]] == [two, three]
        store.upsert_event(event_record(one, "digest-v2"))
        updated = client.get(
            "/api/v1/events",
            headers=AUTH,
            params={"cursor": page2["next_cursor"]},
        ).json()
        assert updated["items"][0]["version"] == 2
        cursor = updated["next_cursor"]
        tampered = cursor[:-3] + ("A" if cursor[-3] != "A" else "B") + cursor[-2:]
        assert (
            client.get(
                "/api/v1/events", headers=AUTH, params={"cursor": tampered}
            ).status_code
            == 400
        )
    restarted = create_app(settings=settings, store=ApiStore(settings.database_path))
    with TestClient(restarted) as client:
        response = client.get(
            "/api/v1/events", headers=AUTH, params={"cursor": cursor}
        )
        assert response.status_code == 200
        assert response.json()["items"] == []


def test_full_source_id_and_artifact_identity_checks(tmp_path):
    root, _, store, app = make_app(tmp_path)
    with TestClient(app) as client:
        assert store.get_event(SOURCE_ID) is not None
        good = client.get(f"/api/v1/events/{SOURCE_ID}/raw", headers=AUTH)
        assert good.status_code == 200
        assert good.json()["source_event_id"] == SOURCE_ID
        assert client.get("/api/v1/events/stable", headers=AUTH).status_code == 404
        assert client.get("/api/v1/events/../bad", headers=AUTH).status_code in {
            404,
            422,
        }
        assert client.get("/api/v1/events/C:/Windows", headers=AUTH).status_code in {
            404,
            422,
        }

        raw_path = root / "data/events/raw/2026-08-13/lazarus-day.events.raw.jsonl"
        raw_path.write_text("{}\n", encoding="utf-8")
        replaced = client.get(f"/api/v1/events/{SOURCE_ID}/raw", headers=AUTH)
        assert replaced.status_code == 409
        assert str(root) not in replaced.text
        raw_path.unlink()
        missing = client.get(f"/api/v1/events/{SOURCE_ID}/raw", headers=AUTH)
        assert missing.status_code == 409


def test_index_is_idempotent_and_path_escape_is_rejected(tmp_path):
    root = make_project(tmp_path)
    settings = make_settings(root)
    store = ApiStore(settings.database_path)
    store.initialize()
    first = index_events(settings, store)
    assert first["indexed"] == 1
    assert first["changed"] == 1
    assert store.count_events() == 1
    assert store.count_changes() == 1
    second = index_events(settings, store)
    assert second["changed"] == 0
    assert store.count_changes() == 1

    raw_path = root / "data/events/raw/2026-08-13/lazarus-day.events.raw.jsonl"
    raw = json.loads(raw_path.read_text(encoding="utf-8"))
    raw["fetched_at"] = "2026-08-13T12:00:00Z"
    raw_path.write_text(json.dumps(raw) + "\n", encoding="utf-8", newline="\n")
    refetched = index_events(settings, store)
    assert refetched["changed"] == 0
    assert store.count_changes() == 1

    failed = raw_path.parent / "lazarus-day.failed-sample.raw.jsonl"
    failed.write_text(
        json.dumps({"source_record_id": "failed-source-id"}) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    with_failure_artifact = index_events(settings, store)
    assert with_failure_artifact["errors"] == []
    assert with_failure_artifact["changed"] == 0

    outside = root.parent / "outside.jsonl"
    outside.write_text("{}\n", encoding="utf-8")
    row = store.get_event(SOURCE_ID)
    assert row is not None
    with store._connect() as connection:
        connection.execute(
            "UPDATE events SET raw_relpath = ? WHERE source_event_id = ?",
            ("../outside.jsonl", SOURCE_ID),
        )
    app = create_app(settings=settings, store=store)
    with TestClient(app) as client:
        response = client.get(f"/api/v1/events/{SOURCE_ID}/raw", headers=AUTH)
    assert response.status_code == 409


@pytest.mark.parametrize(
    ("exit_code", "native_status", "expected"),
    [(0, "completed", "completed"), (1, "failed", "failed")],
)
def test_worker_maps_exit_codes(tmp_path, exit_code, native_status, expected):
    root = make_project(tmp_path)
    settings = make_settings(root)
    store = ApiStore(settings.database_path)
    store.initialize()
    run = create_store_run(store)
    worker = PipelineWorker(settings, store, FakeRunner(
        root, exit_code=exit_code, native_status=native_status
    ))
    worker.worker_id = "test-worker"
    worker._execute(run)
    assert store.get_run(run["id"])["status"] == expected


def test_worker_lock_conflict_and_failure_recovery_items(tmp_path):
    root = make_project(tmp_path)
    settings = make_settings(root)
    store = ApiStore(settings.database_path)
    store.initialize()
    run = create_store_run(store)
    worker = PipelineWorker(
        settings,
        store,
        FakeRunner(root, exit_code=20, missing_manifest=True),
    )
    worker.worker_id = "test-worker"
    worker._execute(run)
    assert store.get_run(run["id"])["status"] == "queued"

    with store._connect() as connection:
        connection.execute(
            "UPDATE runs SET status='failed', completed_at=?, updated_at=? WHERE id=?",
            (utc_now(), utc_now(), run["id"]),
        )
    second_id = "2" * 32
    store.create_run(
        run_id=second_id,
        invocation_id=f"api-{second_id}",
        idempotency_key=None,
        request={"mode": "incremental"},
    )
    claimed = store.claim_next_run("test-worker", lease_seconds=10)
    assert claimed is not None
    recovery_item = {
        "source_event_id": SOURCE_ID,
        "status": "completed_with_review",
        "review_required": True,
    }
    worker = PipelineWorker(
        settings,
        store,
        FakeRunner(root, recovery_items=[recovery_item], native_status="completed_with_review"),
    )
    worker.worker_id = "test-worker"
    worker._execute(claimed)
    item = store.list_run_items(second_id)[0]
    assert item["origin"] == "recovery"
    assert store.get_run(second_id)["status"] == "completed_with_review"


def test_background_worker_uses_fake_runner(tmp_path):
    root = make_project(tmp_path)
    runner = FakeRunner(root)
    settings = make_settings(root, worker_enabled=True)
    store = ApiStore(settings.database_path)
    app = create_app(settings=settings, store=store, runner=runner)
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/runs", headers=AUTH, json={"mode": "incremental"}
        )
        run_id = response.json()["id"]
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            current = client.get(f"/api/v1/runs/{run_id}", headers=AUTH).json()
            if current["status"] in {"completed", "failed"}:
                break
            time.sleep(0.01)
        assert current["status"] == "completed"
    assert len(runner.calls) == 1


def test_fixed_runner_uses_fixed_argv_and_shell_false(tmp_path, monkeypatch):
    root = make_project(tmp_path)
    settings = make_settings(root)
    captured: dict[str, Any] = {}

    class Process:
        pid = 123

        def __init__(self, argv, **kwargs):
            captured["argv"] = argv
            captured["kwargs"] = kwargs

        def wait(self):
            return 0

    monkeypatch.setattr(api_module.subprocess, "Popen", Process)
    invocation = "api-" + "a" * 32
    FixedCollectorRunner(settings).run(
        {
            "invocation_id": invocation,
            "request_json": json.dumps(
                {"command": "Remove-Item", "path": "C:/Windows"}
            ),
        },
        lambda *_: None,
    )
    argv = captured["argv"]
    assert isinstance(argv, list)
    assert captured["kwargs"]["shell"] is False
    assert argv[0] == "python-test"
    assert "--invocation-id" in argv and invocation in argv
    assert "Remove-Item" not in " ".join(argv)
    assert "C:/Windows" not in " ".join(argv)


def test_collector_lock_reports_second_owner(tmp_path):
    lock_path = tmp_path / "collector.lock"
    with exclusive_collector_lock(lock_path):
        with pytest.raises(CollectorLockError):
            with exclusive_collector_lock(lock_path):
                pass


def test_symlink_or_junction_escape_is_rejected(tmp_path):
    root, _, store, app = make_app(tmp_path)
    outside = root.parent / "outside.jsonl"
    outside.write_text("{}\n", encoding="utf-8")
    link = root / "data/events/raw/linked.jsonl"
    try:
        link.symlink_to(outside)
    except OSError as exc:
        pytest.skip(f"test account cannot create symlinks: {exc}")
    with TestClient(app) as client:
        with store._connect() as connection:
            connection.execute(
                "UPDATE events SET raw_relpath = ? WHERE source_event_id = ?",
                ("data/events/raw/linked.jsonl", SOURCE_ID),
            )
        response = client.get(f"/api/v1/events/{SOURCE_ID}/raw", headers=AUTH)
    assert response.status_code == 409


def test_runner_failure_and_missing_manifest_do_not_leak_details(tmp_path):
    for number, runner in enumerate(
        (
            FakeRunner(
                make_project(tmp_path / "exception"),
                error=RuntimeError("secret local detail"),
            ),
            FakeRunner(
                make_project(tmp_path / "missing"),
                missing_manifest=True,
            ),
        ),
        1,
    ):
        root = runner.root
        settings = make_settings(root)
        store = ApiStore(settings.database_path)
        store.initialize()
        run = create_store_run(store, number)
        worker = PipelineWorker(settings, store, runner)
        worker.worker_id = "test-worker"
        worker._execute(run)
        result = store.get_run(run["id"])
        assert result["status"] == "failed"
        assert "secret local detail" not in str(result["error"])


def test_current_new_and_recovery_items_are_all_persisted(tmp_path):
    root = make_project(tmp_path)
    second_id = "another-stable-id"
    third_id = "recovered-stable-id"
    path = root / "data/events/raw/2026-08-13/lazarus-day.events.raw.jsonl"
    first = path.read_text(encoding="utf-8")
    write_raw(root, source_id=second_id)
    second = path.read_text(encoding="utf-8")
    write_raw(root, source_id=third_id)
    third = path.read_text(encoding="utf-8")
    path.write_text(first + second + third, encoding="utf-8", newline="\n")

    settings = make_settings(root)
    store = ApiStore(settings.database_path)
    store.initialize()
    index_events(settings, store)
    with store._connect() as connection:
        old_id = "f" * 32
        now = utc_now()
        connection.execute(
            """
            INSERT INTO runs (
                id, invocation_id, mode, status, request_json,
                created_at, updated_at, available_at, completed_at
            ) VALUES (?, ?, 'incremental', 'failed', '{}', ?, ?, ?, ?)
            """,
            (old_id, f"api-{old_id}", now, now, now, now),
        )
        connection.execute(
            """
            INSERT INTO run_items (
                run_id, source_event_id, origin, status, review_required
            ) VALUES (?, ?, 'current', 'failed', 0)
            """,
            (old_id, third_id),
        )
    run = create_store_run(store, 2)
    runner = FakeRunner(
        root,
        native_status="completed_with_review",
        items=[
            {"source_event_id": SOURCE_ID, "status": "completed"},
            {"source_event_id": second_id, "status": "completed"},
        ],
        recovery_items=[
            {
                "source_event_id": third_id,
                "status": "manual_review",
                "review_required": True,
            }
        ],
    )
    worker = PipelineWorker(settings, store, runner)
    worker.worker_id = "test-worker"
    worker._execute(run)
    items = store.list_run_items(run["id"])
    assert {item["source_event_id"] for item in items} == {
        SOURCE_ID,
        second_id,
        third_id,
    }
    origins = {item["source_event_id"]: item["origin"] for item in items}
    assert origins[third_id] == "recovery"
