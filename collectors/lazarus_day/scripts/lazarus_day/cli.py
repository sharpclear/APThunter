from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
from dataclasses import asdict
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable
from urllib.parse import urlencode

from .client import LazarusHttpClient
from .deduplicator import EventDeduplicator
from .matcher import (
    OrganizationMatcher,
    load_actor_alias_overrides,
    load_organizations,
    read_text_compatible,
)
from .models import (
    COLLECTOR_VERSION,
    BatchStats,
    CollectorError,
    CollectorLockError,
    DateWindow,
    FetchError,
    OriginalSource,
    ParseError,
    ReportRecord,
    ReportSeed,
    ValidationError,
)
from .normalizer import (
    canonicalize_url,
    infer_source_level,
    make_event_key,
    normalize_report,
    validate_event,
)
from .parser import (
    parse_original_source,
    parse_report_detail,
    parse_report_list,
    parse_rss,
    source_record_id_from_url,
)
from .storage import (
    exclusive_collector_lock,
    read_state,
    sha256_file,
    write_batch_outputs,
    write_failure_artifacts,
    write_json,
    write_state,
)


LOGGER = logging.getLogger(__name__)

REPORTS_URL = "https://lazarus.day/reports/"
RSS_URL = "https://lazarus.day/reports/feed/"
DEFAULT_USER_AGENT = (
    "APTHunter-Research-Collector/1.0 (+contact configured by operator)"
)
DEFAULT_SPEC = Path("docs/APT事件数据采集及导入格式规范.md")
RECENT_URL_LIMIT = 500
INVOCATION_ID_RE = re.compile(r"^api-[0-9a-f]{32}$")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "采集 lazarus.day Reports，生成标准化、审核和校验文件；"
            "不会连接数据库。"
        )
    )
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
    parser.add_argument(
        "--actor-overrides",
        type=Path,
        help=(
            "可选的用户确认 Actor 名称映射 CSV；"
            "只影响本次匹配，不修改组织参考文件。"
        ),
    )
    parser.add_argument("--spec", type=Path, default=DEFAULT_SPEC)
    parser.add_argument("--start-date", type=_iso_date)
    parser.add_argument("--end-date", type=_iso_date)
    parser.add_argument("--since-last-success", action="store_true")
    parser.add_argument("--max-pages", type=_positive_int, default=50)
    parser.add_argument("--max-items", type=_positive_int, default=500)
    parser.add_argument("--request-delay", type=_non_negative_float, default=1.0)
    parser.add_argument("--timeout", type=_positive_float, default=20.0)
    parser.add_argument("--output-root", type=Path, default=Path("data/events"))
    parser.add_argument(
        "--state-file",
        type=Path,
        default=Path("data/events/state/lazarus-day.json"),
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--no-fetch-original-source", action="store_true")
    parser.add_argument(
        "--log-level",
        choices=("DEBUG", "INFO", "WARNING", "ERROR"),
        default="INFO",
    )
    parser.add_argument(
        "--user-agent",
        default=os.environ.get("APTHUNTER_USER_AGENT", DEFAULT_USER_AGENT),
        help="可通过 APTHUNTER_USER_AGENT 环境变量配置。",
    )
    parser.add_argument(
        "--invocation-id",
        type=_invocation_id,
        help=(
            "外部调用标识，格式固定为 api- 加 32 位小写十六进制；"
            "用于关联 API manifest 和日志。"
        ),
    )
    return parser


def main(
    argv: list[str] | None = None,
    *,
    client_factory: Callable[..., Any] = LazarusHttpClient,
    now: datetime | None = None,
) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    if args.since_last_success and (args.start_date or args.end_date):
        parser.error(
            "--since-last-success 与 --start-date/--end-date 互斥"
        )
    project_root = Path(__file__).resolve().parents[2]
    lock_path = (
        project_root
        / "data"
        / "events"
        / "state"
        / "lazarus-day.collector.lock"
    )
    try:
        with exclusive_collector_lock(lock_path):
            summary = run(args, client_factory=client_factory, now=now)
    except CollectorLockError as exc:
        LOGGER.warning("%s", exc)
        return 20
    except CollectorError as exc:
        LOGGER.error("%s", exc)
        _write_invocation_manifest(
            args, status="failed", summary=None, error=type(exc).__name__
        )
        return 1
    _write_invocation_manifest(
        args,
        status=(
            "completed_with_review"
            if summary["stats"]["needs_review"]
            else "completed"
        ),
        summary=summary,
        error=None,
    )
    LOGGER.info(
        "批次完成：accepted=%s, needs_review=%s, rejected=%s, dry_run=%s",
        summary["stats"]["accepted"],
        summary["stats"]["needs_review"],
        summary["stats"]["rejected"],
        args.dry_run,
    )
    return 0


def _write_invocation_manifest(
    args: argparse.Namespace,
    *,
    status: str,
    summary: dict[str, Any] | None,
    error: str | None,
) -> None:
    invocation_id = getattr(args, "invocation_id", None)
    if not invocation_id:
        return
    output_root = args.output_root.resolve()
    manifest_path = (
        output_root / "reports" / f"lazarus-day-run-{invocation_id}.json"
    )
    items: list[dict[str, Any]] = []
    if summary is not None:
        raw_path = Path(summary["outputs"]["raw"])
        review_urls: set[str] = set()
        normalized_urls: set[str] = set()
        for key, target in (
            ("needs_review", review_urls),
            ("normalized", normalized_urls),
        ):
            path = Path(summary["outputs"][key])
            if not path.is_file():
                continue
            for line in path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                value = json.loads(line)
                context = value.get("review_context") or {}
                source_url = context.get("lazarus_day_url")
                if source_url:
                    target.add(str(source_url))
        if raw_path.is_file():
            for line in raw_path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                raw = json.loads(line)
                source_id = raw.get("source_record_id")
                source_url = str(raw.get("lazarus_day_url") or "")
                if not source_id:
                    continue
                if raw.get("parse_error"):
                    item_status = "failed"
                elif source_url in normalized_urls:
                    item_status = "completed"
                elif source_url in review_urls:
                    item_status = (
                        "manual_review"
                        if raw.get("match_status") in {"unmatched", "conflict"}
                        else "completed_with_review"
                    )
                else:
                    item_status = "completed"
                items.append(
                    {
                        "source_event_id": source_id,
                        "status": item_status,
                        "review_required": item_status
                        in {"manual_review", "completed_with_review"},
                        "event_candidate": (
                            raw.get("classification") != "rejected"
                            and raw.get("dedup_status") != "exact_duplicate"
                        ),
                    }
                )
    elif status == "failed":
        # API invocations have an isolated output root. Preserve failures with
        # a stable source ID so a later successful retry can be classified as
        # a recovery instead of disappearing into a batch-level error only.
        for raw_path in sorted(output_root.rglob("*.failed-*.raw.jsonl")):
            try:
                lines = raw_path.read_text(encoding="utf-8").splitlines()
            except (OSError, UnicodeError):
                continue
            for line in lines:
                if not line.strip():
                    continue
                try:
                    raw = json.loads(line)
                except json.JSONDecodeError:
                    continue
                source_id = raw.get("source_record_id")
                if not source_id:
                    continue
                items.append(
                    {
                        "source_event_id": source_id,
                        "status": "failed",
                        "review_required": False,
                        "event_candidate": True,
                        "error_kind": "detail_fetch_or_parse",
                        "error": "Native collection item failed.",
                    }
                )
    manifest = {
        "schema_version": "1.0",
        "source": "lazarus.day",
        "invocation_id": invocation_id,
        "status": status,
        "exit_code": 0 if status != "failed" else 1,
        "items": items,
        "recovery_items": [],
        "stats": summary.get("stats", {}) if summary else {},
        "outputs": summary.get("outputs", {}) if summary else {},
        "error": error,
    }
    write_json(manifest_path, manifest)


def run(
    args: argparse.Namespace,
    *,
    client_factory: Callable[..., Any] = LazarusHttpClient,
    now: datetime | None = None,
) -> dict[str, Any]:
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    organizations_path = args.organizations.resolve()
    events_path = args.existing_events.resolve()
    actor_overrides_path = (
        args.actor_overrides.resolve() if args.actor_overrides else None
    )
    spec_path = args.spec.resolve()
    output_root = args.output_root.resolve()
    state_path = args.state_file.resolve()
    _validate_inputs(
        organizations_path,
        events_path,
        spec_path,
        actor_overrides_path,
    )
    input_hashes_before = {
        "organizations": sha256_file(organizations_path),
        "existing_events": sha256_file(events_path),
        "spec": sha256_file(spec_path),
    }
    if actor_overrides_path is not None:
        input_hashes_before["actor_overrides"] = sha256_file(
            actor_overrides_path
        )
    spec_text, spec_encoding = read_text_compatible(spec_path)
    _validate_spec(spec_text, spec_path)
    organizations, organizations_encoding = load_organizations(
        organizations_path
    )
    matcher = OrganizationMatcher(organizations)
    actor_overrides: list[dict[str, object]] = []
    actor_overrides_encoding: str | None = None
    if actor_overrides_path is not None:
        actor_overrides, actor_overrides_encoding = (
            load_actor_alias_overrides(actor_overrides_path, matcher)
        )
    deduplicator = EventDeduplicator.from_csv(events_path)
    state = read_state(state_path)
    window = _resolve_window(args, state, now.date())
    LOGGER.info(
        "采集范围：%s 至 %s（%s）",
        window.start,
        window.end,
        window.mode,
    )
    if spec_path != DEFAULT_SPEC.resolve():
        LOGGER.info("使用数据规范：%s", spec_path)

    stats = BatchStats()
    raw_records: list[dict[str, Any]] = []
    accepted: list[dict[str, Any]] = []
    needs_review: list[dict[str, Any]] = []
    unmatched: list[dict[str, Any]] = []
    rejections: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    processed_urls: list[str] = []

    client = client_factory(
        user_agent=args.user_agent,
        request_delay=args.request_delay,
        timeout=args.timeout,
    )
    try:
        seeds = _discover_reports(client, window, args.max_pages)
        seeds = _filter_and_limit_seeds(seeds, window, args.max_items)
        if args.since_last_success:
            recently_processed = {
                canonicalize_url(value)
                for value in state.get("recent_report_urls", [])
                if isinstance(value, str)
            }
            seeds = [
                seed
                for seed in seeds
                if canonicalize_url(seed.detail_url) not in recently_processed
            ]
        stats.discovered = len(seeds)
        LOGGER.info("待处理报告：%s", len(seeds))

        for seed in seeds:
            detail_result = None
            try:
                detail_result = client.get(seed.detail_url)
                stats.fetched += 1
                report = parse_report_detail(
                    detail_result.body,
                    seed=seed,
                    requested_url=detail_result.requested_url,
                    final_url=detail_result.final_url,
                    http_status=detail_result.status_code,
                    content_sha256=detail_result.content_sha256,
                    fetched_at=detail_result.fetched_at,
                )
            except (FetchError, ParseError) as exc:
                stats.errors += 1
                errors.append(
                    {
                        "url": seed.detail_url,
                        "stage": "detail_fetch_or_parse",
                        "error": f"{type(exc).__name__}: {exc}",
                    }
                )
                raw_records.append(
                    {
                        "source_record_id": source_record_id_from_url(
                            seed.detail_url
                        ),
                        "lazarus_day_url": seed.detail_url,
                        "raw_title": seed.title,
                        "http_status": (
                            detail_result.status_code if detail_result else None
                        ),
                        "content_sha256": (
                            detail_result.content_sha256
                            if detail_result
                            else None
                        ),
                        "fetched_at": (
                            detail_result.fetched_at if detail_result else None
                        ),
                        "parse_error": str(exc),
                        "raw_detail_html": (
                            detail_result.body if detail_result else None
                        ),
                    }
                )
                continue

            original = _fetch_original(
                client,
                report,
                disabled=args.no_fetch_original_source,
            )
            raw_record = _raw_record(report, original)
            match = matcher.match(
                related_actors=report.related_actors,
                tags=report.tags,
                title=report.title,
            )
            normalized = normalize_report(report, match, original)
            if normalized.event is None:
                stats.rejected += 1
                rejection = {
                    "lazarus_day_url": report.lazarus_day_url,
                    "title": report.title,
                    "reason": normalized.rejected_reason,
                }
                rejections.append(rejection)
                raw_record["classification"] = "rejected"
                raw_record["classification_reason"] = normalized.rejected_reason
                raw_records.append(raw_record)
                processed_urls.append(report.lazarus_day_url)
                continue

            event = normalized.event
            event_key = make_event_key(
                canonical_link=str(event["link"]),
                organization_id=event["organization_id"],
                event_date=str(event["event_date"]),
                title=str(event["title"]),
            )
            decision = deduplicator.check_and_register(
                event, lazarus_day_url=report.lazarus_day_url
            )
            raw_record["event_key"] = event_key
            raw_record["match_status"] = match.status
            raw_record["match_method"] = match.method
            raw_record["dedup_status"] = decision.status
            raw_record["dedup_reason"] = decision.reason
            raw_records.append(raw_record)
            processed_urls.append(report.lazarus_day_url)

            if decision.status == "exact_duplicate":
                stats.duplicates += 1
                stats.rejected += 1
                rejections.append(
                    {
                        "lazarus_day_url": report.lazarus_day_url,
                        "title": report.title,
                        "reason": decision.reason,
                        "existing_id": decision.existing_id,
                    }
                )
                continue
            review_reasons = list(normalized.review_reasons)
            if decision.status == "suspected_duplicate":
                stats.suspected_duplicates += 1
                review_reasons.append(decision.reason or "疑似重复")
                event["review_status"] = "needs_review"
                event["collection_notes"] = _append_note(
                    event.get("collection_notes"), decision.reason
                )
            validate_event(
                event,
                allow_partial_date=event["review_status"] == "needs_review",
            )
            stats.normalized += 1
            if event["review_status"] == "accepted":
                accepted.append(event)
                stats.accepted += 1
            else:
                review_record = dict(event)
                review_record["review_context"] = {
                    "reasons": list(dict.fromkeys(review_reasons)),
                    "raw_organization_names": list(match.raw_names),
                    "candidate_organizations": [
                        {"id": item.id, "name": item.name}
                        for item in match.candidate_organizations
                    ],
                    "event_key": event_key,
                    "lazarus_day_url": report.lazarus_day_url,
                    "dedup_existing_id": decision.existing_id,
                }
                needs_review.append(review_record)
                stats.needs_review += 1
                if normalized.unmatched:
                    unmatched.append(review_record)
                    stats.unmatched += 1
        stats.raw_records = len(raw_records)
    finally:
        close = getattr(client, "close", None)
        if callable(close):
            close()

    if errors:
        failure_paths = write_failure_artifacts(
            output_root=output_root,
            raw_records=raw_records,
            errors=errors,
            now=now,
        )
        raise CollectorError(
            "批次包含 lazarus.day 详情获取/解析错误；"
            "未更新规范化输出和 checkpoint。失败记录："
            f"{failure_paths['report']}"
        )

    input_hashes_after = {
        "organizations": sha256_file(organizations_path),
        "existing_events": sha256_file(events_path),
        "spec": sha256_file(spec_path),
    }
    if actor_overrides_path is not None:
        input_hashes_after["actor_overrides"] = sha256_file(
            actor_overrides_path
        )
    if input_hashes_before != input_hashes_after:
        raise CollectorError("只读输入在运行期间发生变化，终止输出")

    validation = {
        "status": "success",
        "collector_version": COLLECTOR_VERSION,
        "generated_at": now.isoformat(),
        "window": {
            "start": window.start.isoformat(),
            "end": window.end.isoformat(),
            "mode": window.mode,
        },
        "dry_run": bool(args.dry_run),
        "database_accessed": False,
        "reference_files_modified": False,
        "checkpoint_updated": not args.dry_run,
        "input_files": {
            "organizations": {
                "path": str(organizations_path),
                "sha256": input_hashes_after["organizations"],
                "encoding": organizations_encoding,
                "rows": len(organizations),
            },
            "existing_events": {
                "path": str(events_path),
                "sha256": input_hashes_after["existing_events"],
                "encoding": deduplicator.encoding,
                "rows": deduplicator.row_count,
            },
            "spec": {
                "path": str(spec_path),
                "sha256": input_hashes_after["spec"],
                "encoding": spec_encoding,
            },
            "actor_overrides": (
                {
                    "path": str(actor_overrides_path),
                    "sha256": input_hashes_after["actor_overrides"],
                    "encoding": actor_overrides_encoding,
                    "rows": len(actor_overrides),
                }
                if actor_overrides_path is not None
                else None
            ),
        },
        "stats": stats.as_dict(),
        "rejections": rejections,
        "errors": [],
    }
    output_paths = write_batch_outputs(
        output_root=output_root,
        batch_date=now.date(),
        raw_records=raw_records,
        accepted=accepted,
        needs_review=needs_review,
        unmatched=unmatched,
        validation=validation,
        stats=stats,
        window_start=window.start,
        window_end=window.end,
        rejections=rejections,
        dry_run=args.dry_run,
    )
    if not args.dry_run:
        recent_urls = _bounded_recent_urls(
            state.get("recent_report_urls", []), processed_urls
        )
        seen_dates = [
            seed.published_date
            for seed in seeds
            if len(seed.published_date) == 10
        ]
        new_state = {
            "last_success_at": now.isoformat(),
            "last_seen_report_date": (
                max(seen_dates)
                if seen_dates
                else state.get("last_seen_report_date")
            ),
            "recent_report_urls": recent_urls,
            "collector_version": COLLECTOR_VERSION,
            "last_batch_stats": stats.as_dict(),
        }
        write_state(state_path, new_state)

    return {
        "stats": stats.as_dict(),
        "outputs": {key: str(value) for key, value in output_paths.items()},
        "checkpoint_updated": not args.dry_run,
    }


def _discover_reports(
    client: Any, window: DateWindow, max_pages: int
) -> list[ReportSeed]:
    feed_seeds: list[ReportSeed] = []
    feed_error: Exception | None = None
    try:
        feed_result = client.get(RSS_URL)
        feed_seeds = parse_rss(feed_result.body)
        LOGGER.info("RSS 发现 %s 条报告", len(feed_seeds))
    except (FetchError, ParseError) as exc:
        feed_error = exc
        LOGGER.warning("RSS 不可用，回退 Reports 列表：%s", exc)

    need_history = not feed_seeds
    if feed_seeds:
        dated = [
            date.fromisoformat(seed.published_date)
            for seed in feed_seeds
            if len(seed.published_date) == 10
        ]
        need_history = not dated or window.start < min(dated)
    list_seeds: list[ReportSeed] = []
    if need_history:
        list_seeds = _discover_from_lists(client, window, max_pages)
    if feed_error and not list_seeds:
        raise CollectorError(
            f"RSS 和 Reports 列表均未能发现报告：{feed_error}"
        )
    by_url: dict[str, ReportSeed] = {}
    for seed in [*feed_seeds, *list_seeds]:
        by_url[canonicalize_url(seed.detail_url)] = seed
    return list(by_url.values())


def _discover_from_lists(
    client: Any, window: DateWindow, max_pages: int
) -> list[ReportSeed]:
    seeds: list[ReportSeed] = []
    pages_used = 0
    current_year = date.today().year
    for year in range(window.end.year, window.start.year - 1, -1):
        base = REPORTS_URL if year == current_year else f"{REPORTS_URL}{year}/"
        page = 1
        while pages_used < max_pages:
            query = urlencode({"page": page})
            page_url = f"{base}?{query}"
            result = client.get(page_url)
            page_seeds = parse_report_list(result.body, page_url)
            pages_used += 1
            seeds.extend(page_seeds)
            full_dates = [
                date.fromisoformat(seed.published_date)
                for seed in page_seeds
                if len(seed.published_date) == 10
            ]
            if full_dates and min(full_dates) < window.start:
                break
            page += 1
        if pages_used >= max_pages:
            LOGGER.warning("达到 --max-pages=%s，停止历史翻页", max_pages)
            break
    LOGGER.info("Reports 列表发现 %s 条候选", len(seeds))
    return seeds


def _filter_and_limit_seeds(
    seeds: Iterable[ReportSeed],
    window: DateWindow,
    max_items: int,
) -> list[ReportSeed]:
    selected = []
    for seed in seeds:
        if len(seed.published_date) != 10:
            selected.append(seed)
            continue
        seed_date = date.fromisoformat(seed.published_date)
        if window.start <= seed_date <= window.end:
            selected.append(seed)
    selected.sort(key=lambda item: item.published_date, reverse=True)
    return selected[:max_items]


def _fetch_original(
    client: Any,
    report: ReportRecord,
    *,
    disabled: bool,
) -> OriginalSource | None:
    if not report.original_url:
        return None
    source_level = infer_source_level(report.publisher, report.original_url)
    if disabled:
        return OriginalSource(
            requested_url=report.original_url,
            final_url=report.original_url,
            http_status=None,
            content_sha256=None,
            fetched_at=report.fetched_at,
            source_level=source_level,
            error="由 --no-fetch-original-source 禁用",
        )
    try:
        result = client.get(report.original_url)
    except FetchError as exc:
        return OriginalSource(
            requested_url=report.original_url,
            final_url=report.original_url,
            http_status=None,
            content_sha256=None,
            fetched_at=report.fetched_at,
            source_level=source_level,
            error=f"{type(exc).__name__}: {exc}",
        )
    if result.body and "html" in result.content_type.casefold():
        return parse_original_source(
            result.body,
            requested_url=result.requested_url,
            final_url=result.final_url,
            http_status=result.status_code,
            content_sha256=result.content_sha256,
            fetched_at=result.fetched_at,
            source_level=source_level,
        )
    return OriginalSource(
        requested_url=result.requested_url,
        final_url=result.final_url,
        http_status=result.status_code,
        content_sha256=result.content_sha256,
        fetched_at=result.fetched_at,
        title=report.title,
        published_date=None,
        source_level=source_level,
    )


def _raw_record(
    report: ReportRecord, original: OriginalSource | None
) -> dict[str, Any]:
    value = {
        "source_record_id": report.source_record_id,
        "lazarus_day_url": report.lazarus_day_url,
        "requested_url": report.requested_url,
        "original_url": report.original_url,
        "raw_title": report.title,
        "raw_summary": report.summary,
        "raw_tags": list(report.tags),
        "raw_related_actors": list(report.related_actors),
        "publisher": report.publisher,
        "published_date": report.published_date,
        "date_precision": report.date_precision,
        "http_status": report.http_status,
        "final_url": report.final_url,
        "content_sha256": report.content_sha256,
        "fetched_at": report.fetched_at,
        "parse_warnings": list(report.parse_warnings),
        "raw_detail_html": report.raw_html,
        "original_source": asdict(original) if original else None,
    }
    return value


def _resolve_window(
    args: argparse.Namespace, state: dict[str, Any], today: date
) -> DateWindow:
    if args.since_last_success:
        state_date = state.get("last_seen_report_date")
        if isinstance(state_date, str):
            try:
                start = date.fromisoformat(state_date)
                return DateWindow(start=start, end=today, mode="since-last-success")
            except ValueError:
                LOGGER.warning("状态中的 last_seen_report_date 无效，使用安全回看")
        LOGGER.warning("没有可用成功状态，--since-last-success 回退最近 7 天")
        return DateWindow(
            start=today - timedelta(days=6),
            end=today,
            mode="safe-default-7-days",
        )
    if args.start_date or args.end_date:
        end = args.end_date or today
        start = args.start_date or (end - timedelta(days=6))
        if start > end:
            raise ValidationError("--start-date 不能晚于 --end-date")
        return DateWindow(start=start, end=end, mode="explicit")
    LOGGER.warning("未指定范围，使用最近 7 天安全回看窗口")
    return DateWindow(
        start=today - timedelta(days=6),
        end=today,
        mode="safe-default-7-days",
    )


def _validate_inputs(
    organizations: Path,
    existing_events: Path,
    spec: Path,
    actor_overrides: Path | None = None,
) -> None:
    for label, path in (
        ("组织文件", organizations),
        ("现有事件文件", existing_events),
        ("数据规范", spec),
    ):
        if not path.is_file():
            raise ValidationError(f"{label}不存在：{path}")
    if actor_overrides is not None and not actor_overrides.is_file():
        raise ValidationError(f"Actor 覆盖文件不存在：{actor_overrides}")


def _validate_spec(text: str, path: Path) -> None:
    required_markers = (
        "schema_version",
        "record_type",
        "organization_id",
        "review_status",
        "evidence",
        "collected_at",
    )
    missing = [marker for marker in required_markers if marker not in text]
    if missing:
        raise ValidationError(
            f"数据规范缺少必要标记 {missing}：{path}"
        )


def _bounded_recent_urls(
    old_values: object, new_values: Iterable[str]
) -> list[str]:
    combined: list[str] = []
    if isinstance(old_values, list):
        combined.extend(value for value in old_values if isinstance(value, str))
    combined.extend(new_values)
    deduped: list[str] = []
    for value in combined:
        canonical = canonicalize_url(value)
        if canonical in deduped:
            deduped.remove(canonical)
        deduped.append(canonical)
    return deduped[-RECENT_URL_LIMIT:]


def _append_note(current: object, note: str | None) -> str | None:
    values = [str(current).strip()] if current else []
    if note:
        values.append(note)
    return "；".join(value for value in values if value) or None


def _iso_date(value: str) -> date:
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("日期必须为 YYYY-MM-DD") from exc


def _invocation_id(value: str) -> str:
    if not INVOCATION_ID_RE.fullmatch(value):
        raise argparse.ArgumentTypeError(
            "invocation ID 必须匹配 api-[0-9a-f]{32}"
        )
    return value


def _positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("必须是整数") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("必须大于 0")
    return parsed


def _positive_float(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("必须是数字") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("必须大于 0")
    return parsed


def _non_negative_float(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("必须是数字") from exc
    if parsed < 0:
        raise argparse.ArgumentTypeError("不能小于 0")
    return parsed


if __name__ == "__main__":
    sys.exit(main())
