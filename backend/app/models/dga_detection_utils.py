from __future__ import annotations

import csv
import os
from urllib.parse import urlsplit


def safe_text(value) -> str:
    if value is None:
        return ""
    return str(value).strip()


def normalize_domain(value: str) -> str:
    candidate = safe_text(value).strip("\"'`<>[](){}")
    if not candidate:
        return ""
    try:
        if "://" in candidate:
            host = urlsplit(candidate).hostname
        elif candidate.startswith("//"):
            host = urlsplit(f"http:{candidate}").hostname
        elif any(separator in candidate for separator in ["/", "?", "#"]):
            host = urlsplit(f"http://{candidate}").hostname
        elif ":" in candidate:
            host = urlsplit(f"//{candidate}").hostname
        else:
            host = candidate
    except ValueError:
        return ""
    if not host:
        return ""
    host = host.strip().strip(".").lower()
    try:
        return host.encode("idna").decode("ascii").lower().strip(".")
    except UnicodeError:
        return host


def extract_sld(domain: str) -> str:
    normalized = normalize_domain(domain)
    if not normalized:
        return ""
    labels = [part for part in normalized.split(".") if part]
    if len(labels) < 2:
        return labels[0] if labels else ""
    return labels[-2]


def read_csv_records(path: str) -> list[dict[str, str]]:
    with open(path, "r", encoding="utf-8-sig", newline="") as handle:
        return [dict(row) for row in csv.DictReader(handle)]


def write_csv_records(path: str, records: list[dict], fieldnames: list[str]) -> None:
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(records)


def require_columns(columns: list[str], required: list[str]) -> None:
    missing = [column for column in required if column not in columns]
    if missing:
        raise ValueError(f"Missing required columns: {missing}")


def require_file_exists(path: str, name: str) -> None:
    if not path or not os.path.isfile(path):
        raise FileNotFoundError(f"{name} does not exist: {path}")


def validate_required_args(values: dict[str, str]) -> None:
    missing = [name for name, value in values.items() if value is None or str(value).strip() == ""]
    if missing:
        raise ValueError(f"Missing required arguments: {missing}")


def safe_int_label(value) -> int:
    text = safe_text(value).lower()
    if text in {"1", "true", "yes", "dga", "malicious"}:
        return 1
    return 0


def add_score_bucket_stats(records: list[dict], reference_records: list[dict] | None = None) -> list[str]:
    source = reference_records if reference_records is not None else records
    buckets = {
        "score_0_0_0_5": 0,
        "score_0_5_0_9": 0,
        "score_0_9_0_99": 0,
        "score_0_99_1_0": 0,
    }
    for record in source:
        try:
            score = float(record.get("dga_like_score", 0))
        except Exception:
            score = 0.0
        if score < 0.5:
            buckets["score_0_0_0_5"] += 1
        elif score < 0.9:
            buckets["score_0_5_0_9"] += 1
        elif score < 0.99:
            buckets["score_0_9_0_99"] += 1
        else:
            buckets["score_0_99_1_0"] += 1
    for record in records:
        record.update(buckets)
    return list(buckets.keys())
