#!/usr/bin/env python3
"""Offline lookup for DGA family to threat actor associations."""

from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
ASSOCIATIONS_CSV = BASE_DIR / "dga_family_actor_associations.csv"
CATALOG_CSV = BASE_DIR / "current_model_dga_family_catalog.csv"
ALIASES_CSV = BASE_DIR / "family_aliases.csv"


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def load_aliases() -> dict[str, str]:
    aliases = {}
    if not ALIASES_CSV.exists():
        return aliases
    for row in read_csv(ALIASES_CSV):
        alias = row.get("alias", "").strip().lower()
        canonical = row.get("canonical_family", "").strip().lower()
        if alias and canonical:
            aliases[alias] = canonical
    return aliases


def normalize_family(value: str, aliases: dict[str, str]) -> str:
    key = value.strip().lower().replace("-", "_")
    return aliases.get(key, key)


def build_lookup() -> tuple[dict[str, dict[str, str]], dict[str, list[dict[str, str]]]]:
    catalog = {row["dga_family"]: row for row in read_csv(CATALOG_CSV)}
    associations: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in read_csv(ASSOCIATIONS_CSV):
        associations[row["dga_family"]].append(row)
    return catalog, associations


def lookup_family(
    family: str,
    catalog: dict[str, dict[str, str]],
    associations: dict[str, list[dict[str, str]]],
    aliases: dict[str, str],
) -> dict[str, object]:
    canonical = normalize_family(family, aliases)
    rows = associations.get(canonical, [])
    return {
        "query": family,
        "canonical_family": canonical,
        "found": canonical in catalog or bool(rows),
        "catalog": catalog.get(canonical),
        "associations": rows,
    }


def normalize_actor(value: str) -> str:
    return " ".join(value.strip().lower().replace("_", " ").split())


def lookup_actor(
    actor: str,
    associations: dict[str, list[dict[str, str]]],
) -> dict[str, object]:
    query = normalize_actor(actor)
    rows = []
    for family_rows in associations.values():
        for row in family_rows:
            actor_name = normalize_actor(row.get("actor_name", ""))
            aliases = [
                normalize_actor(alias)
                for alias in row.get("actor_aliases", "").split(";")
                if alias.strip()
            ]
            if query == actor_name or query in aliases:
                rows.append(row)
    rows.sort(
        key=lambda item: (
            item["dga_family"],
            -float(item["confidence"]),
            item["attribution_status"],
        )
    )
    return {
        "query": actor,
        "found": bool(rows),
        "associations": rows,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Look up offline DGA family to threat actor associations."
    )
    parser.add_argument(
        "--actor",
        action="store_true",
        help="Treat inputs as actor names or aliases and return associated DGA families.",
    )
    parser.add_argument("queries", nargs="+", help="DGA family names, actor names, or aliases")
    args = parser.parse_args()

    aliases = load_aliases()
    catalog, associations = build_lookup()
    if args.actor:
        results = [lookup_actor(query, associations) for query in args.queries]
    else:
        results = [
            lookup_family(query, catalog, associations, aliases)
            for query in args.queries
        ]
    print(json.dumps(results, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
