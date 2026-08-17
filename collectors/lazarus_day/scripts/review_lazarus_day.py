from __future__ import annotations

import argparse
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts.lazarus_day.models import CollectorError
from scripts.lazarus_day.review import (
    accept_matched_review_rows,
    apply_display_decisions,
    apply_actor_alias_overrides,
    export_unknown_organization_rows,
    finalize_review_csv,
    prepare_review_from_raw,
)


LOGGER = logging.getLogger(__name__)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "离线重算 lazarus.day 原始记录、生成 Excel 审核 CSV，"
            "或将已审核 CSV 转换为最终 8 字段事件 CSV。"
        )
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    prepare = subparsers.add_parser(
        "prepare", help="从已有 raw JSONL 离线生成审核文件"
    )
    prepare.add_argument(
        "--raw",
        type=Path,
        action="append",
        required=True,
        help="原始 JSONL；可重复传入以合并多个采集批次。",
    )
    _add_reference_arguments(prepare)
    prepare.add_argument(
        "--output-root", type=Path, default=Path("data/events")
    )
    prepare.add_argument(
        "--actor-overrides",
        type=Path,
        help="用户确认的 Actor 名称映射 CSV。",
    )
    prepare.add_argument(
        "--actor-relationships",
        type=Path,
        help=(
            "用户确认的 Actor 关系与排除决策 CSV；"
            "启用后按 Related Actors 的不同组织拆分事件。"
        ),
    )
    prepare.add_argument(
        "--output-name",
        default="lazarus-day",
        help="输出文件名前缀；用于生成独立的审核快照。",
    )

    accept_matched = subparsers.add_parser(
        "accept-matched",
        help="接受组织 ID/名称已与现有组织索引一致的审核行",
    )
    accept_matched.add_argument(
        "--review-csv",
        type=Path,
        default=Path("data/events/review/lazarus-day.events.review.csv"),
    )
    accept_matched.add_argument(
        "--organizations",
        type=Path,
        default=Path("data/reference/apt_organizations.csv"),
    )
    accept_matched.add_argument(
        "--reviewer-note",
        default="用户确认接受所有有明确组织归属的记录",
    )

    export_unknown = subparsers.add_parser(
        "export-unknown",
        help="导出包含原组织索引之外 Actor 标签的报告",
    )
    export_unknown.add_argument(
        "--review-csv",
        type=Path,
        default=Path(
            "data/events/review/"
            "lazarus-day.events.review.accepted-matched.csv"
        ),
    )
    export_unknown.add_argument("--actor-overrides", type=Path)

    apply_overrides = subparsers.add_parser(
        "apply-overrides",
        help="应用用户确认的 Actor 别名并输出新的审核快照",
    )
    apply_overrides.add_argument("--review-csv", type=Path, required=True)
    apply_overrides.add_argument(
        "--organizations",
        type=Path,
        default=Path("data/reference/apt_organizations.csv"),
    )

    display_decisions = subparsers.add_parser(
        "apply-display-decisions",
        help="将来源核对后的展示标题和描述应用到新的审核快照",
    )
    display_decisions.add_argument("--review-csv", type=Path, required=True)
    display_decisions.add_argument("--decisions-csv", type=Path, required=True)
    display_decisions.add_argument(
        "--organizations",
        type=Path,
        default=Path("data/reference/apt_organizations.csv"),
    )
    display_decisions.add_argument("--output", type=Path, required=True)
    apply_overrides.add_argument(
        "--actor-overrides", type=Path, required=True
    )
    apply_overrides.add_argument("--output", type=Path, required=True)
    apply_overrides.add_argument(
        "--reviewer-note",
        default="用户确认 Actor 名称映射，接受新明确归属记录",
    )
    export_unknown.add_argument(
        "--organizations",
        type=Path,
        default=Path("data/reference/apt_organizations.csv"),
    )
    export_unknown.add_argument(
        "--output",
        type=Path,
        default=Path(
            "data/events/review/"
            "lazarus-day.events.unknown-organizations.csv"
        ),
    )

    finalize = subparsers.add_parser(
        "finalize", help="校验已人工审核的 CSV 并生成最终事件 CSV"
    )
    finalize.add_argument(
        "--review-csv",
        type=Path,
        default=Path("data/events/review/lazarus-day.events.review.csv"),
    )
    _add_reference_arguments(finalize)
    finalize.add_argument(
        "--output",
        type=Path,
        default=Path(
            "data/events/normalized/lazarus-day.events.csv"
        ),
    )
    finalize.add_argument("--report", type=Path)
    finalize.add_argument(
        "--allow-undecided",
        action="store_true",
        help="只导出已接受行，保留未决定行继续待复核。",
    )
    finalize.add_argument(
        "--allow-cross-organization-links",
        action="store_true",
        help="允许同一来源按不同组织拆分为多条事件。",
    )
    parser.add_argument(
        "--log-level",
        choices=("DEBUG", "INFO", "WARNING", "ERROR"),
        default="INFO",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    now = datetime.now(timezone.utc)
    try:
        if args.command == "prepare":
            report = prepare_review_from_raw(
                raw_paths=args.raw,
                organizations_path=args.organizations,
                existing_events_path=args.existing_events,
                output_root=args.output_root,
                actor_overrides_path=args.actor_overrides,
                actor_relationships_path=args.actor_relationships,
                output_name=args.output_name,
                now=now,
            )
            stats = report["stats"]
            LOGGER.info(
                "离线审核文件已生成：accepted=%s, needs_review=%s, "
                "unmatched=%s, rejected=%s",
                stats["accepted"],
                stats["needs_review"],
                stats["unmatched"],
                stats["rejected"],
            )
        elif args.command == "accept-matched":
            result = accept_matched_review_rows(
                review_csv_path=args.review_csv,
                organizations_path=args.organizations,
                reviewer_note=args.reviewer_note,
            )
            LOGGER.info(
                "明确组织归属记录已接受：accepted=%s, pending=%s",
                result["accepted_rows"],
                result["pending_rows"],
            )
        elif args.command == "export-unknown":
            result = export_unknown_organization_rows(
                review_csv_path=args.review_csv,
                organizations_path=args.organizations,
                output_csv_path=args.output,
                actor_overrides_path=args.actor_overrides,
            )
            LOGGER.info(
                "未知组织标签 CSV 已生成：reports=%s, unique_names=%s",
                result["output_rows"],
                result["unique_unknown_organization_names"],
            )
        elif args.command == "apply-overrides":
            result = apply_actor_alias_overrides(
                review_csv_path=args.review_csv,
                organizations_path=args.organizations,
                actor_overrides_path=args.actor_overrides,
                output_csv_path=args.output,
                reviewer_note=args.reviewer_note,
            )
            LOGGER.info(
                "Actor 覆盖已应用：newly_matched=%s, pending=%s",
                result["newly_matched_rows"],
                result["pending_rows"],
            )
        elif args.command == "apply-display-decisions":
            result = apply_display_decisions(
                review_csv_path=args.review_csv,
                decisions_csv_path=args.decisions_csv,
                organizations_path=args.organizations,
                output_csv_path=args.output,
            )
            LOGGER.info(
                "展示文案决策已应用：accepted=%s, rejected=%s, pending=%s",
                result["accepted_rows"],
                result["rejected_rows"],
                result["pending_rows"],
            )
        else:
            report = finalize_review_csv(
                review_csv_path=args.review_csv,
                organizations_path=args.organizations,
                existing_events_path=args.existing_events,
                output_csv_path=args.output,
                report_path=args.report,
                allow_undecided=args.allow_undecided,
                allow_cross_organization_links=(
                    args.allow_cross_organization_links
                ),
                now=now,
            )
            LOGGER.info(
                "最终 CSV 已生成：accepted=%s, rejected=%s",
                report["stats"]["accepted_rows"],
                report["stats"]["rejected_rows"],
            )
    except CollectorError as exc:
        LOGGER.error("%s", exc)
        return 1
    return 0


def _add_reference_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--organizations",
        type=Path,
        default=Path("data/reference/apt_organizations.csv"),
    )
    parser.add_argument(
        "--existing-events",
        type=Path,
        default=Path("data/reference/apt_events.csv"),
    )


if __name__ == "__main__":
    raise SystemExit(main())
