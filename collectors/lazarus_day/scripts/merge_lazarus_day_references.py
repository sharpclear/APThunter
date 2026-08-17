from __future__ import annotations

import argparse
import csv
import io
import json
import shutil
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts.lazarus_day.matcher import normalize_actor_name
from scripts.lazarus_day.storage import atomic_write_text, sha256_file


EVENT_FIELDS = (
    "id",
    "event_date",
    "title",
    "description",
    "threat_type",
    "organization_id",
    "releasing_product",
    "link",
)
TARGET_ORGANIZATIONS = {"52", "53", "54", "55"}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Safely merge reviewed lazarus.day data into reference CSVs."
    )
    parser.add_argument(
        "--organizations",
        type=Path,
        default=Path("data/reference/apt_organizations.csv"),
    )
    parser.add_argument(
        "--events",
        type=Path,
        default=Path("data/reference/apt_events.csv"),
    )
    parser.add_argument(
        "--incoming-events",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--name-baseline",
        type=Path,
        required=True,
    )
    parser.add_argument("--backup-dir", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result = merge_references(
        organizations_path=args.organizations,
        events_path=args.events,
        incoming_events_path=args.incoming_events,
        name_baseline_path=args.name_baseline,
        backup_dir=args.backup_dir,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


def merge_references(
    *,
    organizations_path: Path,
    events_path: Path,
    incoming_events_path: Path,
    name_baseline_path: Path,
    backup_dir: Path,
) -> dict[str, object]:
    organizations_path = _resolve_project_path(organizations_path)
    events_path = _resolve_project_path(events_path)
    incoming_events_path = _resolve_project_path(incoming_events_path)
    name_baseline_path = _resolve_project_path(name_baseline_path)
    backup_dir = _resolve_project_path(backup_dir)
    for path in (
        organizations_path,
        events_path,
        incoming_events_path,
        name_baseline_path,
    ):
        if not path.is_file():
            raise RuntimeError(f"Input file does not exist: {path}")
    if backup_dir.exists():
        raise RuntimeError(f"Backup directory already exists: {backup_dir}")

    hashes_before = {
        "organizations": sha256_file(organizations_path),
        "events": sha256_file(events_path),
        "incoming_events": sha256_file(incoming_events_path),
        "name_baseline": sha256_file(name_baseline_path),
    }
    organization_fields, organizations = _read_csv(organizations_path)
    event_fields, existing_events = _read_csv(events_path)
    incoming_fields, incoming_events = _read_csv(incoming_events_path)
    baseline_fields, baseline_rows = _read_csv(name_baseline_path)
    if tuple(event_fields) != EVENT_FIELDS or tuple(incoming_fields) != EVENT_FIELDS:
        raise RuntimeError("Event CSV fields do not match the required 8-column schema")
    required_organization_fields = {"id", "name", "aliases", "event_count"}
    if not required_organization_fields.issubset(organization_fields):
        raise RuntimeError("Organization CSV is missing required fields")
    required_baseline_fields = {
        "source_name",
        "decision",
        "organization_id",
        "organization_name",
        "alias_eligible",
        "status",
    }
    if not required_baseline_fields.issubset(baseline_fields):
        raise RuntimeError("Name baseline CSV is missing required fields")

    original_organizations = [dict(row) for row in organizations]
    original_events = [dict(row) for row in existing_events]
    organizations_by_id = {row["id"].strip(): row for row in organizations}
    if not TARGET_ORGANIZATIONS.issubset(organizations_by_id):
        raise RuntimeError("One or more target DPRK organizations are missing")

    alias_additions: dict[str, list[str]] = {
        organization_id: [] for organization_id in TARGET_ORGANIZATIONS
    }
    for row in baseline_rows:
        if (
            row["decision"].strip().casefold() != "map"
            or row["alias_eligible"].strip().casefold() != "true"
            or row["status"].strip().casefold() != "active"
        ):
            continue
        organization_id = row["organization_id"].strip()
        if organization_id not in TARGET_ORGANIZATIONS:
            continue
        expected_name = organizations_by_id[organization_id]["name"].strip()
        if row["organization_name"].strip() != expected_name:
            raise RuntimeError(
                f"Baseline organization mismatch: {organization_id}/"
                f"{row['organization_name']}"
            )
        source_name = row["source_name"].strip()
        canonical_name = normalize_actor_name(source_name)
        existing_names = {
            normalize_actor_name(value)
            for value in _split_aliases(
                organizations_by_id[organization_id]["aliases"]
            )
        }
        existing_names.add(normalize_actor_name(expected_name))
        pending_names = {
            normalize_actor_name(value)
            for value in alias_additions[organization_id]
        }
        if canonical_name not in existing_names | pending_names:
            alias_additions[organization_id].append(source_name)

    existing_link_org = {
        (row["link"].strip(), row["organization_id"].strip())
        for row in existing_events
    }
    incoming_link_org: set[tuple[str, str]] = set()
    rows_to_append: list[dict[str, str]] = []
    for line_number, row in enumerate(incoming_events, start=2):
        organization_id = row["organization_id"].strip()
        if organization_id not in TARGET_ORGANIZATIONS:
            raise RuntimeError(
                f"Incoming event line {line_number} is outside the four DPRK organizations"
            )
        if row["id"].strip():
            raise RuntimeError(
                f"Incoming event line {line_number} has a non-empty id"
            )
        key = (row["link"].strip(), organization_id)
        if key in existing_link_org or key in incoming_link_org:
            raise RuntimeError(
                f"Duplicate link and organization in incoming events at line {line_number}"
            )
        incoming_link_org.add(key)
        rows_to_append.append(dict(row))
    combined_events = [*existing_events, *rows_to_append]

    event_counts: dict[str, int] = {}
    for row in combined_events:
        organization_id = row["organization_id"].strip()
        event_counts[organization_id] = event_counts.get(organization_id, 0) + 1
    for organization_id, additions in alias_additions.items():
        organization = organizations_by_id[organization_id]
        aliases = _split_aliases(organization["aliases"])
        aliases.extend(additions)
        organization["aliases"] = " | ".join(aliases)
        organization["event_count"] = str(event_counts.get(organization_id, 0))

    backup_dir.mkdir(parents=True, exist_ok=False)
    organization_backup = backup_dir / organizations_path.name
    events_backup = backup_dir / events_path.name
    shutil.copy2(organizations_path, organization_backup)
    shutil.copy2(events_path, events_backup)
    if sha256_file(organization_backup) != hashes_before["organizations"]:
        raise RuntimeError("Organization backup hash mismatch")
    if sha256_file(events_backup) != hashes_before["events"]:
        raise RuntimeError("Event backup hash mismatch")

    atomic_write_text(
        organizations_path,
        "\ufeff" + _serialize_csv(organization_fields, organizations),
    )
    atomic_write_text(
        events_path,
        "\ufeff" + _serialize_csv(event_fields, combined_events),
    )

    final_organization_fields, final_organizations = _read_csv(
        organizations_path
    )
    final_event_fields, final_events = _read_csv(events_path)
    if final_organization_fields != organization_fields:
        raise RuntimeError("Organization fields changed unexpectedly")
    if final_event_fields != event_fields:
        raise RuntimeError("Event fields changed unexpectedly")
    if final_events[: len(original_events)] != original_events:
        raise RuntimeError("Existing event rows changed unexpectedly")
    if final_events[len(original_events) :] != rows_to_append:
        raise RuntimeError("Appended event rows changed unexpectedly")
    original_by_id = {row["id"]: row for row in original_organizations}
    final_by_id = {row["id"]: row for row in final_organizations}
    for organization_id, original in original_by_id.items():
        current = final_by_id[organization_id]
        changed_fields = {
            field
            for field in organization_fields
            if original[field] != current[field]
        }
        allowed = {"aliases", "event_count"} if organization_id in TARGET_ORGANIZATIONS else set()
        if not changed_fields.issubset(allowed):
            raise RuntimeError(
                f"Unexpected organization changes for id {organization_id}: "
                f"{sorted(changed_fields)}"
            )
    if len(final_events) != len(original_events) + len(rows_to_append):
        raise RuntimeError("Final event row count mismatch")

    return {
        "status": "success",
        "backup_dir": str(backup_dir),
        "organizations": {
            "path": str(organizations_path),
            "rows": len(final_organizations),
            "sha256_before": hashes_before["organizations"],
            "sha256_after": sha256_file(organizations_path),
            "alias_additions": alias_additions,
            "event_counts": {
                organization_id: event_counts.get(organization_id, 0)
                for organization_id in sorted(TARGET_ORGANIZATIONS)
            },
        },
        "events": {
            "path": str(events_path),
            "rows_before": len(original_events),
            "rows_added": len(rows_to_append),
            "rows_after": len(final_events),
            "sha256_before": hashes_before["events"],
            "sha256_after": sha256_file(events_path),
            "new_ids_left_blank": all(
                not row["id"].strip() for row in rows_to_append
            ),
        },
        "database_accessed": False,
    }


def _resolve_project_path(path: Path) -> Path:
    resolved = (PROJECT_ROOT / path).resolve() if not path.is_absolute() else path.resolve()
    try:
        resolved.relative_to(PROJECT_ROOT.resolve())
    except ValueError as exc:
        raise RuntimeError(f"Path is outside the project root: {resolved}") from exc
    return resolved


def _read_csv(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None:
            raise RuntimeError(f"CSV has no header: {path}")
        fields = list(reader.fieldnames)
        return fields, [
            {field: row.get(field) or "" for field in fields} for row in reader
        ]


def _serialize_csv(
    fieldnames: list[str], rows: list[dict[str, str]]
) -> str:
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(
        buffer, fieldnames=fieldnames, lineterminator="\n"
    )
    writer.writeheader()
    writer.writerows(rows)
    return buffer.getvalue()


def _split_aliases(value: str) -> list[str]:
    return [part.strip() for part in value.split("|") if part.strip()]


if __name__ == "__main__":
    raise SystemExit(main())
