from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Literal


OutputKind = Literal[
    "final_results",
    "active_learning",
    "model_diagnostics",
    "audits",
    "manual_review_backfill",
    "experiments",
]

ARCHIVE_DIRS: dict[OutputKind, str] = {
    "final_results": "final_results",
    "active_learning": "active_learning",
    "model_diagnostics": "model_diagnostics",
    "audits": "audits",
    "manual_review_backfill": "manual_review_backfill",
    "experiments": "experiments",
}

GENERIC_STEMS = {
    "suspicious_domains_result",
    "suspicious_domains_result_unique_candidates",
    "prediction_report",
    "review_candidates",
    "test_predictions",
    "false_positives",
    "false_negatives",
    "eval_test_overall",
    "train_features",
    "valid_features",
    "test_features",
    "all_features",
    "feature_columns",
}


def today_string() -> str:
    return datetime.now().strftime("%Y-%m-%d")


def normalize_date(value: str | None) -> str:
    if not value:
        return today_string()
    text = value.strip()
    match = re.fullmatch(r"(\d{4})[-_/](\d{1,2})[-_/](\d{1,2})", text)
    if match:
        year, month, day = match.groups()
        return f"{int(year):04d}-{int(month):02d}-{int(day):02d}"
    match = re.fullmatch(r"(\d{4})(\d{2})(\d{2})", text)
    if match:
        year, month, day = match.groups()
        return f"{year}-{month}-{day}"
    return slugify(text, fallback=today_string())


def slugify(value: str | Path | None, fallback: str = "task") -> str:
    if value is None:
        return fallback
    text = Path(value).stem if isinstance(value, Path) else str(value)
    text = text.strip().lower()
    text = re.sub(r"[^a-z0-9._-]+", "_", text)
    text = re.sub(r"_+", "_", text).strip("._-")
    return text or fallback


def task_dir_from_archived_path(path: str | Path | None) -> str:
    if not path:
        return ""
    input_path = Path(path)
    parent = input_path.parent
    if parent.name and parent.parent.name in set(ARCHIVE_DIRS.values()):
        return parent.name
    return ""


def build_task_id(
    task_date: str | None = None,
    task_name: str | None = None,
    source_path: str | Path | None = None,
    default_task_name: str = "",
    reuse_archived_parent: bool = True,
) -> str:
    if reuse_archived_parent:
        archived = task_dir_from_archived_path(source_path)
        if archived and not task_date and not task_name:
            return archived

    date_part = normalize_date(task_date)
    name = slugify(task_name, fallback="") if task_name else ""
    if not name and source_path:
        inferred = slugify(Path(source_path).stem, fallback="")
        if inferred not in GENERIC_STEMS:
            name = inferred
    if not name and default_task_name:
        name = slugify(default_task_name, fallback="")
    return f"{date_part}_{name}" if name else date_part


def build_output_dir(
    kind: OutputKind,
    output_root: str | Path = "outputs",
    task_date: str | None = None,
    task_name: str | None = None,
    source_path: str | Path | None = None,
    default_task_name: str = "",
) -> Path:
    task_id = build_task_id(
        task_date=task_date,
        task_name=task_name,
        source_path=source_path,
        default_task_name=default_task_name,
    )
    return Path(output_root) / ARCHIVE_DIRS[kind] / task_id


def resolve_output_file(
    explicit_path: str | Path | None,
    kind: OutputKind,
    filename: str,
    output_root: str | Path = "outputs",
    task_date: str | None = None,
    task_name: str | None = None,
    source_path: str | Path | None = None,
    default_task_name: str = "",
) -> Path:
    if explicit_path:
        return Path(explicit_path)
    return build_output_dir(
        kind=kind,
        output_root=output_root,
        task_date=task_date,
        task_name=task_name,
        source_path=source_path,
        default_task_name=default_task_name,
    ) / filename


def resolve_output_dir(
    explicit_dir: str | Path | None,
    kind: OutputKind,
    output_root: str | Path = "outputs",
    task_date: str | None = None,
    task_name: str | None = None,
    source_path: str | Path | None = None,
    default_task_name: str = "",
) -> Path:
    if explicit_dir:
        return Path(explicit_dir)
    return build_output_dir(
        kind=kind,
        output_root=output_root,
        task_date=task_date,
        task_name=task_name,
        source_path=source_path,
        default_task_name=default_task_name,
    )
