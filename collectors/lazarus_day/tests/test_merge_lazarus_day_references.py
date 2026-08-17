from __future__ import annotations

import csv
from pathlib import Path

import scripts.merge_lazarus_day_references as merge_module


EVENT_HEADER = (
    "id,event_date,title,description,threat_type,organization_id,"
    "releasing_product,link\n"
)


def test_merge_updates_only_direct_aliases_and_appends_blank_id_events(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setattr(merge_module, "PROJECT_ROOT", tmp_path)
    organizations = tmp_path / "organizations.csv"
    organizations.write_text(
        "id,name,aliases,event_count\n"
        "52,APT38,Bluenoroff,1\n"
        "53,Kimsuky,APT43,0\n"
        "54,APT37,ScarCruft,0\n"
        "55,Lazarus Group,ZINC,0\n",
        encoding="utf-8",
        newline="\n",
    )
    events = tmp_path / "events.csv"
    events.write_text(
        EVENT_HEADER
        +
        "1,2026-01-01,old,old,APT攻击,52,old,https://example/old\n",
        encoding="utf-8",
        newline="\n",
    )
    incoming = tmp_path / "incoming.csv"
    incoming.write_text(
        EVENT_HEADER
        +
        ",2026-08-01,new53,new53,APT攻击,53,new,https://example/shared\n"
        ",2026-08-01,new55,new55,APT攻击,55,new,https://example/shared\n",
        encoding="utf-8",
        newline="\n",
    )
    baseline = tmp_path / "baseline.csv"
    baseline.write_text(
        "source_name,decision,organization_id,organization_name,"
        "alias_eligible,status\n"
        "Ruby Sleet,map,53,Kimsuky,true,active\n"
        "Contagious Interview,map,55,Lazarus Group,false,active\n"
        "JINX-0164,exclude,,,false,excluded\n",
        encoding="utf-8",
        newline="\n",
    )
    backup = tmp_path / "backup"
    result = merge_module.merge_references(
        organizations_path=organizations,
        events_path=events,
        incoming_events_path=incoming,
        name_baseline_path=baseline,
        backup_dir=backup,
    )
    assert result["events"]["rows_after"] == 3
    with organizations.open("r", encoding="utf-8-sig", newline="") as handle:
        organization_rows = {row["id"]: row for row in csv.DictReader(handle)}
    assert organization_rows["53"]["aliases"] == "APT43 | Ruby Sleet"
    assert "Contagious Interview" not in organization_rows["55"]["aliases"]
    assert organization_rows["52"]["event_count"] == "1"
    assert organization_rows["53"]["event_count"] == "1"
    assert organization_rows["55"]["event_count"] == "1"
    with events.open("r", encoding="utf-8-sig", newline="") as handle:
        event_rows = list(csv.DictReader(handle))
    assert [row["id"] for row in event_rows] == ["1", "", ""]
    assert (backup / "organizations.csv").is_file()
    assert (backup / "events.csv").is_file()
