from __future__ import annotations

import hashlib
import json
import os
import tempfile
from contextlib import contextmanager
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .models import BatchStats, CollectorError, CollectorLockError


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


@contextmanager
def exclusive_collector_lock(path: Path):
    """Hold a cross-process one-byte lock without deleting the lock file."""

    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = path.open("a+b")
    try:
        handle.seek(0, os.SEEK_END)
        if handle.tell() == 0:
            handle.write(b"0")
            handle.flush()
        handle.seek(0)
        try:
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise CollectorLockError(
                "another collector process is already running"
            ) from exc
        try:
            yield
        finally:
            handle.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    finally:
        handle.close()


def read_state(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        with path.open("r", encoding="utf-8") as handle:
            value = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise CollectorError(f"状态文件无法读取：{path}: {exc}") from exc
    if not isinstance(value, dict):
        raise CollectorError(f"状态文件根节点必须是对象：{path}")
    return value


def atomic_write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    normalized = content.replace("\r\n", "\n").replace("\r", "\n")
    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temp_path = Path(handle.name)
            handle.write(normalized)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
    except OSError as exc:
        if temp_path is not None and temp_path.exists():
            temp_path.unlink()
        raise CollectorError(f"无法原子写入文件：{path}: {exc}") from exc


def write_jsonl(path: Path, records: Iterable[dict[str, Any]]) -> None:
    lines = [
        json.dumps(record, ensure_ascii=False, separators=(",", ":"))
        for record in records
    ]
    content = "\n".join(lines)
    if lines:
        content += "\n"
    atomic_write_text(path, content)


def write_json(path: Path, value: dict[str, Any]) -> None:
    atomic_write_text(
        path,
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
    )


def write_batch_outputs(
    *,
    output_root: Path,
    batch_date: date,
    raw_records: list[dict[str, Any]],
    accepted: list[dict[str, Any]],
    needs_review: list[dict[str, Any]],
    unmatched: list[dict[str, Any]],
    validation: dict[str, Any],
    stats: BatchStats,
    window_start: date,
    window_end: date,
    rejections: list[dict[str, Any]],
    dry_run: bool,
) -> dict[str, Path]:
    date_text = batch_date.isoformat()
    paths = {
        "raw": (
            output_root
            / "raw"
            / date_text
            / "lazarus-day.events.raw.jsonl"
        ),
        "normalized": (
            output_root / "normalized" / "lazarus-day.events.jsonl"
        ),
        "needs_review": (
            output_root
            / "review"
            / "lazarus-day.events.needs-review.jsonl"
        ),
        "unmatched": (
            output_root
            / "review"
            / "lazarus-day.events.unmatched-organizations.jsonl"
        ),
        "validation": (
            output_root
            / "reports"
            / f"lazarus-day-validation-{date_text}.json"
        ),
        "collection": (
            output_root
            / "reports"
            / f"lazarus-day-collection-{date_text}.md"
        ),
    }
    write_jsonl(paths["raw"], raw_records)
    write_jsonl(paths["normalized"], accepted)
    write_jsonl(paths["needs_review"], needs_review)
    write_jsonl(paths["unmatched"], unmatched)
    write_json(paths["validation"], validation)
    atomic_write_text(
        paths["collection"],
        render_collection_report(
            stats=stats,
            window_start=window_start,
            window_end=window_end,
            rejections=rejections,
            dry_run=dry_run,
        ),
    )
    return paths


def write_state(path: Path, state: dict[str, Any]) -> None:
    write_json(path, state)


def write_failure_artifacts(
    *,
    output_root: Path,
    raw_records: list[dict[str, Any]],
    errors: list[dict[str, Any]],
    now: datetime | None = None,
) -> dict[str, Path]:
    now = now or datetime.now(timezone.utc)
    date_text = now.date().isoformat()
    stamp = now.strftime("%Y%m%dT%H%M%SZ")
    paths = {
        "raw": (
            output_root
            / "raw"
            / date_text
            / f"lazarus-day.failed-{stamp}.raw.jsonl"
        ),
        "report": (
            output_root
            / "reports"
            / f"lazarus-day-failure-{stamp}.json"
        ),
    }
    write_jsonl(paths["raw"], raw_records)
    write_json(
        paths["report"],
        {
            "status": "failed",
            "failed_at": now.isoformat(),
            "errors": errors,
            "canonical_outputs_updated": False,
            "checkpoint_updated": False,
        },
    )
    return paths


def render_collection_report(
    *,
    stats: BatchStats,
    window_start: date,
    window_end: date,
    rejections: list[dict[str, Any]],
    dry_run: bool,
) -> str:
    rows = "\n".join(
        f"| {key} | {value} |" for key, value in stats.as_dict().items()
    )
    rejection_lines = []
    for record in rejections[:100]:
        rejection_lines.append(
            f"- `{record.get('lazarus_day_url', '')}`："
            f"{record.get('reason', '未说明')}"
        )
    if len(rejections) > 100:
        rejection_lines.append(
            f"- 另有 {len(rejections) - 100} 条拒绝记录，详见 validation JSON。"
        )
    if not rejection_lines:
        rejection_lines.append("- 无")
    return (
        "# lazarus.day 采集报告\n\n"
        f"- 采集范围：`{window_start.isoformat()}` 至 "
        f"`{window_end.isoformat()}`\n"
        f"- 运行模式：`{'dry-run' if dry_run else 'apply-output'}`\n"
        f"- checkpoint 更新：`{'否' if dry_run else '批次全部成功后更新'}`\n\n"
        "## 统计\n\n"
        "| 指标 | 数量 |\n"
        "|---|---:|\n"
        f"{rows}\n\n"
        "## 拒绝条目\n\n"
        f"{chr(10).join(rejection_lines)}\n"
    )
