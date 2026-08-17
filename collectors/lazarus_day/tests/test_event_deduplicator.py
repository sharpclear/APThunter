from __future__ import annotations

from pathlib import Path

from scripts.lazarus_day.deduplicator import (
    EventDeduplicator,
    normalize_legacy_date,
)


HEADER = (
    "id,event_date,title,description,threat_type,"
    "organization_id,releasing_product,link\n"
)


def _event(
    *,
    link: str = "https://example.com/new",
    title: str = "Kimsuky相关钓鱼攻击活动",
    event_date: str = "2026-07-23",
) -> dict[str, object]:
    return {
        "link": link,
        "organization_id": 53,
        "event_date": event_date,
        "title": title,
    }


def test_reads_gb18030_and_legacy_date_and_blocks_duplicate(
    tmp_path: Path,
) -> None:
    path = tmp_path / "events.csv"
    content = (
        HEADER
        + "1,2026/7/23,Kimsuky相关钓鱼攻击活动,描述,钓鱼攻击,"
        "53,AhnLab,https://example.com/report?utm_source=test\n"
    )
    path.write_bytes(content.encode("gb18030"))
    deduplicator = EventDeduplicator.from_csv(path)
    decision = deduplicator.check_and_register(
        _event(link="https://example.com/report"),
        lazarus_day_url="https://lazarus.day/reports/example-AbC12/",
    )
    assert deduplicator.encoding == "GB18030"
    assert normalize_legacy_date("2026/7/3") == "2026-07-03"
    assert decision.status == "exact_duplicate"
    assert decision.existing_id == "1"


def test_batch_duplicate_and_same_day_suspected_duplicate(
    tmp_path: Path,
) -> None:
    path = tmp_path / "events.csv"
    path.write_text(HEADER, encoding="utf-8", newline="\n")
    deduplicator = EventDeduplicator.from_csv(path)
    first = deduplicator.check_and_register(
        _event(),
        lazarus_day_url="https://lazarus.day/reports/one-AbC12/",
    )
    exact = deduplicator.check_and_register(
        _event(),
        lazarus_day_url="https://lazarus.day/reports/one-AbC12/",
    )
    suspected = deduplicator.check_and_register(
        _event(
            link="https://example.com/other",
            title="Kimsuky相关恶意软件活动",
        ),
        lazarus_day_url="https://lazarus.day/reports/two-DeF34/",
    )
    assert first.status == "unique"
    assert exact.status == "exact_duplicate"
    assert suspected.status == "suspected_duplicate"
