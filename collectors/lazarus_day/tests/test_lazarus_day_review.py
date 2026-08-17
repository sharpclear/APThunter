from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from scripts.lazarus_day.models import ValidationError
from scripts.lazarus_day.review import (
    FINAL_CSV_FIELDS,
    accept_matched_review_rows,
    apply_actor_alias_overrides,
    apply_display_decisions,
    export_unknown_organization_rows,
    finalize_review_csv,
    prepare_review_from_raw,
)


NOW = datetime(2026, 7, 31, 8, 0, tzinfo=timezone.utc)
DETAIL_URL = "https://lazarus.day/reports/newcluster-backdoor-AbC12/"
SOURCE_URL = "https://research.example/newcluster-backdoor"
EVENTS_HEADER = (
    "id,event_date,title,description,threat_type,"
    "organization_id,releasing_product,link\n"
)


def _references(tmp_path: Path) -> tuple[Path, Path]:
    organizations = tmp_path / "organizations.csv"
    organizations.write_text(
        "id,name,aliases\n"
        "53,Kimsuky,Black Banshee | APT43\n",
        encoding="utf-8",
        newline="\n",
    )
    existing_events = tmp_path / "events.csv"
    existing_events.write_text(
        EVENTS_HEADER,
        encoding="utf-8",
        newline="\n",
    )
    return organizations, existing_events


def _raw_record() -> dict[str, object]:
    return {
        "source_record_id": "newcluster-backdoor-AbC12",
        "lazarus_day_url": DETAIL_URL,
        "requested_url": DETAIL_URL,
        "original_url": SOURCE_URL,
        "raw_title": "NewCluster deploys a malicious backdoor",
        "raw_summary": "The actor delivered a backdoor in a phishing campaign.",
        "raw_tags": ["Backdoor", "T1059.001", "Phishing"],
        "raw_related_actors": ["NewCluster"],
        "publisher": "Research Example",
        "published_date": "2026-07-23",
        "date_precision": "day",
        "http_status": 200,
        "final_url": DETAIL_URL,
        "content_sha256": "a" * 64,
        "fetched_at": NOW.isoformat(),
        "parse_warnings": [],
        "raw_detail_html": "<html><h1>NewCluster backdoor</h1></html>",
        "original_source": {
            "requested_url": SOURCE_URL,
            "final_url": SOURCE_URL,
            "http_status": 200,
            "content_sha256": "b" * 64,
            "fetched_at": NOW.isoformat(),
            "title": "NewCluster backdoor report",
            "published_date": "2026-07-23",
            "summary": "The report documents a malicious backdoor.",
            "source_level": "B",
            "raw_html": "<html><title>report</title></html>",
            "error": None,
        },
    }


def _prepare(tmp_path: Path) -> tuple[dict[str, object], Path, Path, Path]:
    organizations, existing_events = _references(tmp_path)
    raw_path = tmp_path / "raw.jsonl"
    raw_path.write_text(
        json.dumps(_raw_record(), ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    output_root = tmp_path / "output"
    report = prepare_review_from_raw(
        raw_path=raw_path,
        organizations_path=organizations,
        existing_events_path=existing_events,
        output_root=output_root,
        now=NOW,
    )
    review_csv = output_root / "review" / "lazarus-day.events.review.csv"
    return report, review_csv, organizations, existing_events


def test_offline_prepare_generates_excel_review_csv_without_network(
    tmp_path: Path,
) -> None:
    report, review_csv, _organizations, _existing_events = _prepare(tmp_path)
    assert report["network_accessed"] is False
    assert report["database_accessed"] is False
    assert report["checkpoint_updated"] is False
    assert report["stats"]["needs_review"] == 1
    assert report["stats"]["unmatched"] == 1
    assert review_csv.read_bytes().startswith(b"\xef\xbb\xbf")

    rows = list(
        csv.DictReader(
            io.StringIO(review_csv.read_text(encoding="utf-8-sig"), newline="")
        )
    )
    assert len(rows) == 1
    assert rows[0]["review_decision"] == ""
    assert rows[0]["raw_related_actors"] == "NewCluster"
    assert rows[0]["raw_tags"] == "Backdoor | T1059.001 | Phishing"
    assert "T1059.001" not in rows[0]["raw_related_actors"]


def test_completed_review_csv_generates_strict_final_csv(
    tmp_path: Path,
) -> None:
    _report, review_csv, organizations, existing_events = _prepare(tmp_path)
    text = review_csv.read_text(encoding="utf-8-sig")
    rows = list(csv.DictReader(io.StringIO(text, newline="")))
    rows[0].update(
        {
            "review_decision": "接受",
            "reviewer_notes": "已核对原始来源与组织归属",
            "organization_id": "53",
            "organization_name": "Kimsuky",
            "event_date": "2026-07-23",
            "date_precision": "publication_date",
            "title": "Kimsuky开展恶意软件投递活动",
            "description": "公开报告记录了Kimsuky投递恶意后门的活动。",
            "threat_type": "恶意软件",
        }
    )
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(
        buffer,
        fieldnames=rows[0].keys(),
        lineterminator="\n",
    )
    writer.writeheader()
    writer.writerows(rows)
    review_csv.write_text(
        "\ufeff" + buffer.getvalue(),
        encoding="utf-8",
        newline="\n",
    )

    output_csv = tmp_path / "lazarus-day.events.csv"
    report = finalize_review_csv(
        review_csv_path=review_csv,
        organizations_path=organizations,
        existing_events_path=existing_events,
        output_csv_path=output_csv,
        now=NOW,
    )
    assert report["stats"]["accepted_rows"] == 1
    final_rows = list(
        csv.DictReader(
            io.StringIO(output_csv.read_text(encoding="utf-8"), newline="")
        )
    )
    assert tuple(final_rows[0]) == FINAL_CSV_FIELDS
    assert final_rows[0]["id"] == ""
    assert final_rows[0]["organization_id"] == "53"
    assert final_rows[0]["title"] == "Kimsuky开展恶意软件投递活动"


def test_undecided_review_rows_block_final_output(tmp_path: Path) -> None:
    _report, review_csv, organizations, existing_events = _prepare(tmp_path)
    output_csv = tmp_path / "lazarus-day.events.csv"
    with pytest.raises(ValidationError, match="review_decision"):
        finalize_review_csv(
            review_csv_path=review_csv,
            organizations_path=organizations,
            existing_events_path=existing_events,
            output_csv_path=output_csv,
            now=NOW,
        )
    assert not output_csv.exists()


def test_accept_matched_and_partial_export_preserve_pending_rows(
    tmp_path: Path,
) -> None:
    _report, review_csv, organizations, existing_events = _prepare(tmp_path)
    rows = list(
        csv.DictReader(
            io.StringIO(
                review_csv.read_text(encoding="utf-8-sig"), newline=""
            )
        )
    )
    pending = dict(rows[0])
    pending["event_key"] = "pending"
    pending["organization_id"] = ""
    pending["organization_name"] = "未匹配组织"
    rows[0]["organization_id"] = "53"
    rows[0]["organization_name"] = "Kimsuky"
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(
        buffer,
        fieldnames=rows[0].keys(),
        lineterminator="\n",
    )
    writer.writeheader()
    writer.writerows([rows[0], pending])
    review_csv.write_text(
        "\ufeff" + buffer.getvalue(),
        encoding="utf-8",
        newline="\n",
    )

    marked = accept_matched_review_rows(
        review_csv_path=review_csv,
        organizations_path=organizations,
        reviewer_note="用户确认明确组织归属记录",
    )
    assert marked["accepted_rows"] == 1
    assert marked["pending_rows"] == 1
    marked_rows = list(
        csv.DictReader(
            io.StringIO(
                review_csv.read_text(encoding="utf-8-sig"), newline=""
            )
        )
    )
    assert marked_rows[0]["review_decision"] == "接受"
    assert marked_rows[1]["review_decision"] == ""

    output_csv = tmp_path / "lazarus-day.events.csv"
    report = finalize_review_csv(
        review_csv_path=review_csv,
        organizations_path=organizations,
        existing_events_path=existing_events,
        output_csv_path=output_csv,
        allow_undecided=True,
        now=NOW,
    )
    assert report["partial_export"] is True
    assert report["stats"]["accepted_rows"] == 1
    assert report["stats"]["undecided_rows"] == 1


def test_unknown_actor_export_excludes_known_aliases(
    tmp_path: Path,
) -> None:
    _report, review_csv, organizations, _existing_events = _prepare(tmp_path)
    rows = list(
        csv.DictReader(
            io.StringIO(
                review_csv.read_text(encoding="utf-8-sig"), newline=""
            )
        )
    )
    known_alias = dict(rows[0])
    known_alias["event_key"] = "known"
    known_alias["raw_related_actors"] = "APT43"
    mixed = dict(rows[0])
    mixed["event_key"] = "mixed"
    mixed["raw_related_actors"] = "APT43 | NewCluster"
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(
        buffer,
        fieldnames=rows[0].keys(),
        lineterminator="\n",
    )
    writer.writeheader()
    writer.writerows([known_alias, mixed])
    review_csv.write_text(
        "\ufeff" + buffer.getvalue(),
        encoding="utf-8",
        newline="\n",
    )

    output_csv = tmp_path / "unknown.csv"
    result = export_unknown_organization_rows(
        review_csv_path=review_csv,
        organizations_path=organizations,
        output_csv_path=output_csv,
    )
    assert result["source_rows"] == 2
    assert result["output_rows"] == 1
    assert result["unknown_organization_names"] == ["NewCluster"]
    output_rows = list(
        csv.DictReader(
            io.StringIO(output_csv.read_text(encoding="utf-8-sig"))
        )
    )
    assert output_rows[0]["unknown_organization_names"] == "NewCluster"
    assert output_rows[0]["known_organization_matches"] == "APT43=>53:Kimsuky"


def test_confirmed_actor_override_updates_a_new_review_snapshot(
    tmp_path: Path,
) -> None:
    _report, review_csv, organizations, _existing_events = _prepare(tmp_path)
    overrides = tmp_path / "overrides.csv"
    overrides.write_text(
        "source_name,organization_id,organization_name,reason\n"
        "NewCluster,53,Kimsuky,user confirmed test mapping\n",
        encoding="utf-8",
        newline="\n",
    )
    output_csv = tmp_path / "corrected-review.csv"
    result = apply_actor_alias_overrides(
        review_csv_path=review_csv,
        organizations_path=organizations,
        actor_overrides_path=overrides,
        output_csv_path=output_csv,
        reviewer_note="confirmed mapping",
    )
    assert result["newly_matched_rows"] == 1
    assert result["pending_rows"] == 0
    rows = list(
        csv.DictReader(
            io.StringIO(output_csv.read_text(encoding="utf-8-sig"))
        )
    )
    assert rows[0]["organization_id"] == "53"
    assert rows[0]["organization_name"] == "Kimsuky"
    assert rows[0]["review_decision"] == "接受"


def test_display_decisions_apply_publishable_copy_to_new_snapshot(
    tmp_path: Path,
) -> None:
    _report, review_csv, organizations, _existing_events = _prepare(tmp_path)
    source_bytes = review_csv.read_bytes()
    rows = list(
        csv.DictReader(
            io.StringIO(review_csv.read_text(encoding="utf-8-sig"))
        )
    )
    rows[0]["organization_id"] = "53"
    rows[0]["organization_name"] = "Kimsuky"
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(
        buffer,
        fieldnames=rows[0].keys(),
        lineterminator="\n",
    )
    writer.writeheader()
    writer.writerows(rows)
    review_csv.write_text(
        "\ufeff" + buffer.getvalue(),
        encoding="utf-8",
        newline="\n",
    )
    source_bytes = review_csv.read_bytes()

    decisions_csv = tmp_path / "display-decisions.csv"
    decisions_csv.write_text(
        "event_key,review_decision,reviewer_notes,title,description,threat_type\n"
        f"{rows[0]['event_key']},接受,已核对原始来源,"
        "Kimsuky利用恶意链接投递后门,"
        "公开报告披露，Kimsuky通过钓鱼链接向目标投递恶意后门。,钓鱼攻击\n",
        encoding="utf-8",
        newline="\n",
    )
    output_csv = tmp_path / "display-review.csv"
    result = apply_display_decisions(
        review_csv_path=review_csv,
        decisions_csv_path=decisions_csv,
        organizations_path=organizations,
        output_csv_path=output_csv,
    )

    assert result["accepted_rows"] == 1
    assert result["pending_rows"] == 0
    assert review_csv.read_bytes() == source_bytes
    output_rows = list(
        csv.DictReader(
            io.StringIO(output_csv.read_text(encoding="utf-8-sig"))
        )
    )
    assert output_rows[0]["review_decision"] == "接受"
    assert output_rows[0]["title"] == "Kimsuky利用恶意链接投递后门"
    assert "人工" not in output_rows[0]["description"]


def test_display_decisions_reject_internal_process_wording(
    tmp_path: Path,
) -> None:
    _report, review_csv, organizations, _existing_events = _prepare(tmp_path)
    rows = list(
        csv.DictReader(
            io.StringIO(review_csv.read_text(encoding="utf-8-sig"))
        )
    )
    rows[0]["organization_id"] = "53"
    rows[0]["organization_name"] = "Kimsuky"
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(
        buffer,
        fieldnames=rows[0].keys(),
        lineterminator="\n",
    )
    writer.writeheader()
    writer.writerows(rows)
    review_csv.write_text(
        "\ufeff" + buffer.getvalue(),
        encoding="utf-8",
        newline="\n",
    )
    decisions_csv = tmp_path / "invalid-display-decisions.csv"
    decisions_csv.write_text(
        "event_key,review_decision,reviewer_notes,title,description,threat_type\n"
        f"{rows[0]['event_key']},接受,已核对原始来源,"
        "Kimsuky利用恶意链接投递后门,"
        "Kimsuky发动攻击，具体技术细节应由人工依据原始报告复核。,钓鱼攻击\n",
        encoding="utf-8",
        newline="\n",
    )
    output_csv = tmp_path / "invalid-display-review.csv"

    with pytest.raises(ValidationError, match="内部流程措辞"):
        apply_display_decisions(
            review_csv_path=review_csv,
            decisions_csv_path=decisions_csv,
            organizations_path=organizations,
            output_csv_path=output_csv,
        )
    assert not output_csv.exists()
