from __future__ import annotations

import argparse
import csv
import hashlib
import logging
import os
import random
import re
import sys
import tempfile
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any, Iterable, Sequence
from urllib.parse import parse_qs, quote, urljoin, urlsplit

try:
    from .core import (
        CheckpointStore,
        EventRecord,
        MetadataRecord,
        MetadataStore,
        Organization,
        append_review_csv,
        event_duplicate_decision,
        load_events,
        load_organizations,
        match_platform_actor,
        new_metadata_record,
        normalize_actor_name,
        normalize_report_publisher,
        normalize_title,
        parse_cli_date,
        parse_report_date,
        safe_url_for_storage,
        sanitize_filename,
        utc_now_iso,
        validate_pdf,
    )
except ImportError:
    from core import (  # type: ignore[no-redef]
        CheckpointStore,
        EventRecord,
        MetadataRecord,
        MetadataStore,
        Organization,
        append_review_csv,
        event_duplicate_decision,
        load_events,
        load_organizations,
        match_platform_actor,
        new_metadata_record,
        normalize_actor_name,
        normalize_report_publisher,
        normalize_title,
        parse_cli_date,
        parse_report_date,
        safe_url_for_storage,
        sanitize_filename,
        utc_now_iso,
        validate_pdf,
    )


PROJECT_ROOT = Path(__file__).resolve().parents[2]
APT_URL = "https://ti.qianxin.com/apt/apt"
PAGE_TIMEOUT_MS = 60_000
DOWNLOAD_TIMEOUT_MS = 90_000
MANUAL_FIELDS = [
    "organization_id",
    "organization_name",
    "platform_actor_name",
    "actor_detail_url",
    "report_title",
    "report_date_raw",
    "reason",
    "collected_at",
]
UNMATCHED_FIELDS = [
    "organization_id",
    "organization_name",
    "aliases",
    "reason",
    "collected_at",
]
DUPLICATE_FIELDS = [
    "organization_id",
    "organization_name",
    "platform_actor_name",
    "report_title",
    "report_date",
    "preview_url",
    "pdf_url",
    "reason",
    "collected_at",
]


@dataclass(frozen=True)
class AppPaths:
    root: Path
    organizations_csv: Path
    events_csv: Path
    reports: Path
    metadata: Path
    review: Path
    state: Path
    browser_profile: Path
    download_temp: Path
    logs: Path
    reports_jsonl: Path
    reports_csv: Path
    checkpoint: Path
    page_audit: Path
    manual_review: Path
    unmatched_review: Path
    duplicate_review: Path

    @classmethod
    def from_root(cls, root: Path) -> "AppPaths":
        data = root / "data"
        reference = data / "reference"
        metadata = data / "metadata"
        review = data / "review"
        state = data / "state"
        return cls(
            root=root,
            organizations_csv=reference / "apt_organizations.csv",
            events_csv=reference / "apt_events.csv",
            reports=data / "reports",
            metadata=metadata,
            review=review,
            state=state,
            browser_profile=state / "browser-profile",
            download_temp=state / "download-temp",
            logs=root / "logs",
            reports_jsonl=metadata / "qianxin-reports.jsonl",
            reports_csv=metadata / "qianxin-reports.csv",
            checkpoint=state / "qianxin-checkpoint.json",
            page_audit=metadata / "qianxin-page-audit.md",
            manual_review=review / "qianxin-manual-download.csv",
            unmatched_review=review / "qianxin-unmatched-organizations.csv",
            duplicate_review=review / "qianxin-possible-duplicates.csv",
        )

    def ensure_directories(self) -> None:
        for path in (
            self.organizations_csv.parent,
            self.reports,
            self.metadata,
            self.review,
            self.browser_profile,
            self.download_temp,
            self.logs,
            self.root / "tests" / "fixtures",
        ):
            path.mkdir(parents=True, exist_ok=True)


@dataclass(frozen=True)
class MatchedActor:
    organization: Organization
    platform_name: str
    match_method: str
    actor_detail_url: str = ""


@dataclass(frozen=True)
class ReportRow:
    row_index: int
    report_date_raw: str
    report_title: str
    report_publisher: str = ""


@dataclass(frozen=True)
class PdfCapture:
    data: bytes
    preview_url: str
    pdf_url: str
    method: str


@dataclass
class AuditObservation:
    actor_count: int = 0
    selected_actor: str = ""
    actor_detail_url: str = ""
    table_headers: list[str] = field(default_factory=list)
    report_count_text: str = ""
    first_page_dates: list[str] = field(default_factory=list)
    descending: bool | None = None
    preview_title: str = ""
    preview_url: str = ""
    pdf_content_type: str = ""
    pdf_loading_method: str = "未检查"
    notes: list[str] = field(default_factory=list)


class AccessPausedError(RuntimeError):
    pass


def redact_message(value: object) -> str:
    text = str(value)
    text = re.sub(
        r"(?i)(x-amz-(?:signature|credential|security-token)|token|signature)=([^&\s]+)",
        r"\1=<redacted>",
        text,
    )
    return text[:1000]


def configure_logging(paths: AppPaths) -> logging.Logger:
    logger = logging.getLogger("qianxin-downloader")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    file_handler = logging.FileHandler(
        paths.logs / "qianxin-downloader.log", encoding="utf-8"
    )
    file_handler.setFormatter(formatter)
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)
    return logger


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="奇安信威胁情报平台 APT 历史报告 PDF 自动下载器",
    )
    parser.add_argument("--login-only", action="store_true", help="打开持久化浏览器供手动登录")
    parser.add_argument(
        "--mode",
        choices=("audit", "backfill", "incremental"),
        default="audit",
        help="安全起见默认仅审计一项，不保存 PDF",
    )
    browser_group = parser.add_mutually_exclusive_group()
    browser_group.add_argument(
        "--headed", dest="headless", action="store_false", help="显示浏览器"
    )
    browser_group.add_argument(
        "--headless", dest="headless", action="store_true", help="隐藏浏览器"
    )
    parser.set_defaults(headless=True)
    parser.add_argument("--dry-run", action="store_true", help="筛选和去重，但不打开预览或下载")
    parser.add_argument("--resume", action="store_true", help="回填模式跳过已完成组织并复用检查点")
    parser.add_argument("--organization-id", help="只处理指定 CSV 组织 id")
    parser.add_argument("--organization-name", help="只处理指定 CSV 组织名称或别名")
    parser.add_argument("--max-organizations", type=positive_int, help="最多处理的组织数")
    parser.add_argument(
        "--max-reports-per-organization", type=positive_int, help="每个组织最多处理的日期范围内报告数"
    )
    parser.add_argument("--start-date", default="2026-04-01", help="完整发布日期下界")
    parser.add_argument("--end-date", default="today", help="完整发布日期上界")
    parser.add_argument(
        "--page-timeout",
        type=positive_int,
        default=PAGE_TIMEOUT_MS,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--download-timeout",
        type=positive_int,
        default=DOWNLOAD_TIMEOUT_MS,
        help=argparse.SUPPRESS,
    )
    return parser


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("必须是大于 0 的整数")
    return parsed


def validate_args(
    parser: argparse.ArgumentParser, args: argparse.Namespace
) -> tuple[date, date]:
    if args.login_only and args.headless:
        parser.error("--login-only 必须与 --headed 一起使用")
    try:
        start_date = parse_cli_date(args.start_date)
        end_date = parse_cli_date(args.end_date)
    except ValueError as exc:
        parser.error(str(exc))
    if start_date > end_date:
        parser.error("--start-date 不能晚于 --end-date")
    if end_date > date.today():
        parser.error("--end-date 不能晚于程序运行当天")
    return start_date, end_date


def ensure_reference_files(paths: AppPaths) -> None:
    missing = [
        path
        for path in (paths.organizations_csv, paths.events_csv)
        if not path.is_file()
    ]
    if missing:
        names = "、".join(str(path.relative_to(paths.root)) for path in missing)
        raise FileNotFoundError(f"缺少只读参考文件：{names}")


def select_organizations(
    organizations: Sequence[Organization], args: argparse.Namespace
) -> list[Organization]:
    selected = list(organizations)
    if args.organization_id:
        selected = [org for org in selected if org.id == str(args.organization_id)]
    if args.organization_name:
        wanted = normalize_actor_name(args.organization_name)
        selected = [
            org
            for org in selected
            if wanted == normalize_actor_name(org.name)
            or any(wanted == normalize_actor_name(alias) for alias in org.aliases)
        ]
    if not selected:
        raise ValueError("参考 CSV 中没有找到指定组织")
    return selected


def launch_persistent_context(
    playwright: Any, paths: AppPaths, args: argparse.Namespace, logger: logging.Logger
):
    options = dict(
        user_data_dir=str(paths.browser_profile),
        headless=args.headless,
        accept_downloads=True,
        downloads_path=str(paths.download_temp),
        viewport={"width": 1440, "height": 1000},
        locale="zh-CN",
        timezone_id="Asia/Shanghai",
    )
    failures = []
    for channel in ("chrome", "msedge", None):
        try:
            kwargs = dict(options)
            if channel:
                kwargs["channel"] = channel
            context = playwright.chromium.launch_persistent_context(**kwargs)
            logger.info("浏览器已启动（%s）", channel or "Playwright Chromium")
            return context
        except Exception as exc:
            failures.append(f"{channel or 'bundled'}: {type(exc).__name__}")
    raise RuntimeError(
        "无法启动 Chromium。请安装 Chrome/Edge，或在项目内设置 "
        "PLAYWRIGHT_BROWSERS_PATH 后执行 python -m playwright install chromium。"
        f" 尝试结果：{', '.join(failures)}"
    )


def goto_apt_page(page: Any, timeout_ms: int) -> None:
    page.goto(APT_URL, wait_until="domcontentloaded", timeout=timeout_ms)
    page.get_by_text("APT组织画像", exact=True).first.wait_for(
        state="visible", timeout=timeout_ms
    )
    # The navigation shell appears before the APT micro-frontend. Waiting for an
    # actor item prevents a fast next step from treating a still-empty map as an
    # unmatched organization.
    page.locator("main li[tabindex='0']").first.wait_for(
        state="visible", timeout=timeout_ms
    )
    page.wait_for_timeout(1_000)


def check_access(page: Any, *, headed: bool, logger: logging.Logger) -> None:
    current = page.url.casefold()
    body = page.locator("body").inner_text(timeout=10_000)
    blocked_markers = ("安全验证", "访问受限", "访问过于频繁", "操作频繁", "验证码")
    login_redirect = "user.ti.qianxin.com/login" in current
    if not login_redirect and not any(marker in body for marker in blocked_markers):
        return
    if headed and sys.stdin.isatty():
        logger.warning("检测到登录/验证码/访问限制页面。请在浏览器中人工处理；程序不会绕过验证。")
        input("处理完成后按 Enter 继续，或按 Ctrl+C 退出：")
        return
    raise AccessPausedError("检测到登录、验证码或访问限制；请先使用 --login-only --headed 人工处理")


def platform_actor_names(page: Any) -> list[str]:
    names: list[str] = []
    seen: set[str] = set()
    for index in range(page.locator("main li[tabindex='0']").count()):
        locator = page.locator("main li[tabindex='0']").nth(index)
        try:
            name = locator.inner_text().strip()
        except Exception:
            continue
        if name and name not in seen:
            names.append(name)
            seen.add(name)
    return names


def platform_actor_detail_urls(context: Any, timeout_ms: int) -> dict[str, str]:
    """Return stable detail routes from the directory request used by the visible map."""
    endpoint = (
        "https://ti.qianxin.com/alpha-api/v2/apt-dossier/actor/all"
        "?lang=zh-CN&source=apt"
    )
    try:
        response = context.request.get(endpoint, timeout=timeout_ms)
        if not response.ok:
            return {}
        payload = response.json()
    except Exception:
        return {}
    data = payload.get("data", []) if isinstance(payload, dict) else []
    routes: dict[str, str] = {}
    for item in data if isinstance(data, list) else []:
        if not isinstance(item, dict):
            continue
        actor_name = str(item.get("actorName", "")).strip()
        actor_id = str(item.get("name", "")).strip()
        if actor_name and actor_id:
            routes[
                actor_name
            ] = f"https://ti.qianxin.com/apt/detail/{actor_id}?type=map"
    return routes


def match_selected_actors(
    actor_names: Sequence[str],
    all_organizations: Sequence[Organization],
    selected: Sequence[Organization],
    detail_urls: dict[str, str] | None = None,
) -> tuple[list[MatchedActor], list[Organization]]:
    selected_ids = {org.id for org in selected}
    priority = {"exact_name": 0, "exact_alias": 1, "normalized_name_or_alias": 2}
    candidates: dict[str, list[MatchedActor]] = {}
    for platform_name in actor_names:
        organization, method = match_platform_actor(platform_name, all_organizations)
        if organization is None or organization.id not in selected_ids:
            continue
        candidates.setdefault(organization.id, []).append(
            MatchedActor(
                organization,
                platform_name,
                method,
                (detail_urls or {}).get(platform_name, ""),
            )
        )
    selected_order = {org.id: index for index, org in enumerate(selected)}
    matches = []
    for org_id, values in candidates.items():
        values.sort(
            key=lambda value: (
                priority.get(value.match_method, 99),
                value.platform_name,
            )
        )
        matches.append(values[0])
    matches.sort(key=lambda value: selected_order[value.organization.id])
    matched_ids = {match.organization.id for match in matches}
    unmatched = [org for org in selected if org.id not in matched_ids]
    return matches, unmatched


def record_unmatched(
    paths: AppPaths, organizations: Iterable[Organization], reason: str
) -> None:
    existing: set[tuple[str, str]] = set()
    if paths.unmatched_review.exists():
        with paths.unmatched_review.open(
            "r", encoding="utf-8-sig", newline=""
        ) as handle:
            for row in csv.DictReader(handle):
                existing.add(
                    (str(row.get("organization_id", "")), str(row.get("reason", "")))
                )
    for org in organizations:
        key = (org.id, reason)
        if key in existing:
            continue
        append_review_csv(
            paths.unmatched_review,
            UNMATCHED_FIELDS,
            {
                "organization_id": org.id,
                "organization_name": org.name,
                "aliases": " | ".join(org.aliases),
                "reason": reason,
                "collected_at": utc_now_iso(),
            },
        )
        existing.add(key)


def open_actor_detail(page: Any, actor_name: str, timeout_ms: int) -> str:
    locator = page.get_by_text(actor_name, exact=True)
    if locator.count() != 1:
        raise RuntimeError(f"组织入口定位不唯一（匹配数 {locator.count()}）")
    locator.click(timeout=timeout_ms)
    page.get_by_role("tab", name="历史报告", exact=True).wait_for(
        state="visible", timeout=timeout_ms
    )
    return page.url


def open_history_tab(page: Any, timeout_ms: int) -> None:
    tab = page.get_by_role("tab", name="历史报告", exact=True)
    tab.click(timeout=timeout_ms)
    page.get_by_text("报告名称", exact=True).wait_for(state="visible", timeout=timeout_ms)
    page.wait_for_timeout(1_000)


def history_headers(page: Any) -> list[str]:
    return [
        page.locator("table thead th").nth(index).inner_text().strip()
        for index in range(page.locator("table thead th").count())
    ]


def report_rows(page: Any) -> list[ReportRow]:
    results = []
    rows = page.locator("table tbody tr")
    for index in range(rows.count()):
        row = rows.nth(index)
        cells = row.locator("td")
        if cells.count() < 3:
            continue
        report_date_raw = cells.nth(1).inner_text().strip()
        button = cells.nth(2).locator("button")
        report_title = (
            button.inner_text() if button.count() else cells.nth(2).inner_text()
        ).strip()
        report_publisher = normalize_report_publisher(
            cells.nth(3).inner_text() if cells.count() >= 4 else ""
        )
        results.append(
            ReportRow(index, report_date_raw, report_title, report_publisher)
        )
    return results


def dates_are_descending(rows: Sequence[ReportRow]) -> bool:
    parsed = [parse_report_date(row.report_date_raw) for row in rows]
    complete = [item for item in parsed if item is not None]
    return len(complete) == len(parsed) and complete == sorted(complete, reverse=True)


def report_title_button(page: Any, row_index: int, title: str):
    rows = page.locator("table tbody tr")
    if row_index >= rows.count():
        raise RuntimeError("报告行在页面更新后消失")
    button = rows.nth(row_index).locator("td").nth(2).locator("button")
    if button.count() != 1 or normalize_title(button.inner_text()) != normalize_title(
        title
    ):
        candidate = page.get_by_role("button", name=title, exact=True)
        if candidate.count() != 1:
            raise RuntimeError("报告标题按钮定位失败或不唯一")
        return candidate
    return button


def close_preview_dialog(page: Any) -> None:
    buttons = page.locator("button[aria-label='Close']:visible")
    if buttons.count():
        try:
            buttons.last.click(timeout=5_000)
            page.wait_for_timeout(300)
        except Exception:
            pass


def report_identifier_from_url(url: str) -> str:
    try:
        values = parse_qs(urlsplit(url).query)
        if values.get("name"):
            return values["name"][0]
    except ValueError:
        pass
    return ""


def build_preview_url(actor_detail_url: str, pdf_url: str, report_title: str) -> str:
    stable_pdf_url = safe_url_for_storage(pdf_url)
    if stable_pdf_url:
        # Qianxin does not expose a separate address-bar URL for its modal preview;
        # the iframe resource itself is the only stable, addressable preview URL.
        return stable_pdf_url
    report_id = report_identifier_from_url(pdf_url)
    identity = (
        report_id or hashlib.sha256(report_title.encode("utf-8")).hexdigest()[:16]
    )
    separator = "&" if "?" in actor_detail_url else "?"
    return f"{actor_detail_url.split('#', 1)[0]}{separator}history_report_id={quote(identity)}"


def audit_report_preview(
    page: Any,
    row: ReportRow,
    actor_detail_url: str,
    timeout_ms: int,
) -> tuple[str, str, str]:
    responses: list[tuple[str, str]] = []

    def on_response(response: Any) -> None:
        content_type = response.headers.get("content-type", "")
        if (
            "pdf" in content_type.casefold()
            or ".pdf" in response.url.casefold()
            or "apt-report" in response.url
        ):
            responses.append((response.url, content_type))

    page.on("response", on_response)
    try:
        report_title_button(page, row.row_index, row.report_title).click(
            timeout=timeout_ms
        )
        iframe = page.locator("iframe[title='Embedded PDF']:visible").last
        iframe.wait_for(state="attached", timeout=timeout_ms)
        iframe_src = urljoin(page.url, iframe.get_attribute("src") or "")
        page.wait_for_timeout(2_000)
        content_type = ""
        for response_url, candidate_type in responses:
            if response_url == iframe_src or "pdf" in candidate_type.casefold():
                content_type = candidate_type
                break
        preview_url = build_preview_url(actor_detail_url, iframe_src, row.report_title)
        return preview_url, safe_url_for_storage(iframe_src), content_type
    finally:
        page.remove_listener("response", on_response)
        close_preview_dialog(page)


def capture_pdf(
    page: Any,
    context: Any,
    row: ReportRow,
    actor_detail_url: str,
    paths: AppPaths,
    timeout_ms: int,
) -> PdfCapture:
    responses: list[tuple[str, str]] = []
    downloads: list[Any] = []

    def on_response(response: Any) -> None:
        content_type = response.headers.get("content-type", "")
        lowered = response.url.casefold()
        if (
            "pdf" in content_type.casefold()
            or ".pdf" in lowered
            or "apt-report" in lowered
        ):
            responses.append((response.url, content_type))

    def on_download(download: Any) -> None:
        downloads.append(download)

    page.on("response", on_response)
    page.on("download", on_download)
    iframe_urls: list[str] = []
    try:
        report_title_button(page, row.row_index, row.report_title).click(
            timeout=timeout_ms
        )
        page.wait_for_timeout(500)
        iframe = page.locator("iframe[title='Embedded PDF']:visible").last
        try:
            iframe.wait_for(state="attached", timeout=timeout_ms)
        except Exception:
            if not downloads and not responses:
                raise RuntimeError("PDF 预览未出现，且没有捕获到下载或 PDF 响应")
        for selector, attribute in (
            ("iframe", "src"),
            ("embed", "src"),
            ("object", "data"),
        ):
            locators = page.locator(f"{selector}:visible")
            for index in range(locators.count()):
                value = locators.nth(index).get_attribute(attribute) or ""
                if value:
                    iframe_urls.append(urljoin(page.url, value))
        page.wait_for_timeout(1_500)

        for download in downloads:
            temp_path: Path | None = None
            try:
                with tempfile.NamedTemporaryFile(
                    dir=paths.download_temp, suffix=".download", delete=False
                ) as handle:
                    temp_path = Path(handle.name)
                download.save_as(str(temp_path))
                data = temp_path.read_bytes()
                if data.startswith(b"%PDF-"):
                    stable = next((url for url in iframe_urls if url), download.url)
                    return PdfCapture(
                        data,
                        build_preview_url(actor_detail_url, stable, row.report_title),
                        safe_url_for_storage(stable),
                        "playwright_download_event",
                    )
            finally:
                if temp_path and temp_path.exists():
                    temp_path.unlink()

        candidates: list[tuple[str, str]] = []
        candidates.extend(
            (url, "application_pdf_response")
            for url, ct in responses
            if "pdf" in ct.casefold()
        )
        candidates.extend(
            (url, "dot_pdf_response_url")
            for url, _ in responses
            if ".pdf" in urlsplit(url).path.casefold()
        )
        candidates.extend((url, "embedded_pdf_url") for url in iframe_urls)
        candidates.extend((url, "blob_backing_pdf_response") for url, _ in responses)
        attempted: set[str] = set()
        for candidate_url, method in candidates:
            if not candidate_url or candidate_url in attempted:
                continue
            attempted.add(candidate_url)
            if candidate_url.startswith(("blob:", "data:", "chrome-extension:")):
                continue
            try:
                response = context.request.get(candidate_url, timeout=timeout_ms)
                if not response.ok:
                    continue
                data = response.body()
            except Exception:
                continue
            if data.startswith(b"%PDF-"):
                stable = next(
                    (url for url in iframe_urls if "apt-report" in url), candidate_url
                )
                return PdfCapture(
                    data,
                    build_preview_url(actor_detail_url, stable, row.report_title),
                    safe_url_for_storage(stable),
                    method,
                )
        raise RuntimeError("未能从下载事件、PDF 响应、.pdf URL 或嵌入元素取得原始 PDF")
    finally:
        page.remove_listener("response", on_response)
        page.remove_listener("download", on_download)
        close_preview_dialog(page)


def relative_path(path: Path, root: Path) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()


def find_local_path_for_sha(metadata: MetadataStore, sha256: str, root: Path) -> str:
    for row in reversed(metadata.rows):
        if str(row.get("sha256", "")).casefold() != sha256.casefold():
            continue
        local = str(row.get("local_path", ""))
        if local and (root / Path(local)).exists():
            return local
    return ""


def save_pdf(
    paths: AppPaths,
    organization: Organization,
    report_date: str,
    report_title: str,
    sha256: str,
    data: bytes,
) -> tuple[Path, bool]:
    folder_name = f"{sanitize_filename(organization.id, max_length=40)}_{sanitize_filename(organization.name, max_length=80)}"
    target_dir = paths.reports / folder_name
    target_dir.mkdir(parents=True, exist_ok=True)
    title = sanitize_filename(report_title, max_length=100)
    base = f"{report_date}_{title}_{sha256[:8]}"
    target = target_dir / f"{base}.pdf"
    if target.exists():
        if hashlib.sha256(target.read_bytes()).hexdigest() == sha256:
            return target, False
        counter = 2
        while (target_dir / f"{base}_{counter}.pdf").exists():
            counter += 1
        target = target_dir / f"{base}_{counter}.pdf"
    with tempfile.NamedTemporaryFile(
        dir=target_dir, suffix=".part", delete=False
    ) as handle:
        temporary = Path(handle.name)
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    if target.exists():
        temporary.unlink(missing_ok=True)
        raise FileExistsError(f"拒绝覆盖已有文件：{target.name}")
    os.replace(temporary, target)
    return target, True


def append_manual_review(
    paths: AppPaths,
    match: MatchedActor,
    actor_detail_url: str,
    row: ReportRow,
    reason: str,
) -> None:
    append_review_csv(
        paths.manual_review,
        MANUAL_FIELDS,
        {
            "organization_id": match.organization.id,
            "organization_name": match.organization.name,
            "platform_actor_name": match.platform_name,
            "actor_detail_url": actor_detail_url,
            "report_title": row.report_title,
            "report_date_raw": row.report_date_raw,
            "reason": reason,
            "collected_at": utc_now_iso(),
        },
    )


def append_possible_duplicate(
    paths: AppPaths,
    match: MatchedActor,
    row: ReportRow,
    report_date: str,
    preview_url: str,
    pdf_url: str,
    reason: str,
) -> None:
    append_review_csv(
        paths.duplicate_review,
        DUPLICATE_FIELDS,
        {
            "organization_id": match.organization.id,
            "organization_name": match.organization.name,
            "platform_actor_name": match.platform_name,
            "report_title": row.report_title,
            "report_date": report_date,
            "preview_url": preview_url,
            "pdf_url": pdf_url,
            "reason": reason,
            "collected_at": utc_now_iso(),
        },
    )


def base_record(
    match: MatchedActor, actor_detail_url: str, row: ReportRow, report_date: str = ""
) -> dict[str, object]:
    return {
        "organization_id": match.organization.id,
        "organization_name": match.organization.name,
        "platform_actor_name": match.platform_name,
        "actor_detail_url": actor_detail_url,
        "report_title": row.report_title,
        "report_publisher": row.report_publisher,
        "report_date": report_date,
    }


def write_status(
    metadata: MetadataStore,
    stats: Counter[str],
    record: MetadataRecord,
    logger: logging.Logger,
) -> None:
    metadata.append(record)
    stats[record.download_status] += 1
    logger.info(
        "组织 %s / 报告 %s / 状态 %s%s",
        record.organization_id,
        record.report_title,
        record.download_status,
        f" ({record.duplicate_reason})" if record.duplicate_reason else "",
    )


def process_report(
    page: Any,
    context: Any,
    paths: AppPaths,
    match: MatchedActor,
    actor_detail_url: str,
    row: ReportRow,
    normalized_date: str,
    args: argparse.Namespace,
    events: Sequence[EventRecord],
    metadata: MetadataStore,
    checkpoint: CheckpointStore,
    stats: Counter[str],
    methods: Counter[str],
    logger: logging.Logger,
) -> bool:
    common = base_record(match, actor_detail_url, row, normalized_date)
    duplicate = metadata.preflight_duplicate(
        match.organization.id, row.report_title, normalized_date
    )
    if duplicate:
        write_status(
            metadata,
            stats,
            new_metadata_record(
                **common,
                download_status=duplicate.status,
                duplicate_reason=duplicate.reason,
            ),
            logger,
        )
        return True
    event_decision = event_duplicate_decision(
        match.organization.id, normalized_date, row.report_title, (), events
    )
    if event_decision:
        if event_decision.status == "manual_required":
            append_possible_duplicate(
                paths, match, row, normalized_date, "", "", event_decision.reason
            )
        write_status(
            metadata,
            stats,
            new_metadata_record(
                **common,
                download_status=event_decision.status,
                duplicate_reason=event_decision.reason,
            ),
            logger,
        )
        return event_decision.status != "manual_required"
    if args.dry_run:
        write_status(
            metadata,
            stats,
            new_metadata_record(
                **common, download_status="skipped", duplicate_reason="dry_run"
            ),
            logger,
        )
        return True
    try:
        capture = capture_pdf(
            page, context, row, actor_detail_url, paths, args.download_timeout
        )
        methods[capture.method] += 1
        url_duplicate = metadata.preflight_duplicate(
            match.organization.id,
            row.report_title,
            normalized_date,
            capture.preview_url,
            capture.pdf_url,
        )
        if url_duplicate or checkpoint.is_processed_url(
            capture.preview_url, capture.pdf_url
        ):
            reason = (
                url_duplicate.reason if url_duplicate else "checkpoint_processed_url"
            )
            record = new_metadata_record(
                **common,
                preview_url=capture.preview_url,
                pdf_url=capture.pdf_url,
                download_status="already_exists",
                duplicate_reason=reason,
            )
            write_status(metadata, stats, record, logger)
            checkpoint.mark_report(capture.preview_url, capture.pdf_url)
            return True
        event_decision = event_duplicate_decision(
            match.organization.id,
            normalized_date,
            row.report_title,
            (capture.preview_url, capture.pdf_url),
            events,
        )
        if event_decision:
            if event_decision.status == "manual_required":
                append_possible_duplicate(
                    paths,
                    match,
                    row,
                    normalized_date,
                    capture.preview_url,
                    capture.pdf_url,
                    event_decision.reason,
                )
            record = new_metadata_record(
                **common,
                preview_url=capture.preview_url,
                pdf_url=capture.pdf_url,
                download_status=event_decision.status,
                duplicate_reason=event_decision.reason,
            )
            write_status(metadata, stats, record, logger)
            if event_decision.status == "duplicate_event":
                checkpoint.mark_report(capture.preview_url, capture.pdf_url)
                return True
            return False
        validation = validate_pdf(capture.data)
        if (
            validation.sha256 in metadata.sha256s
            or validation.sha256 in checkpoint.sha256s
        ):
            local_path = find_local_path_for_sha(
                metadata, validation.sha256, paths.root
            )
            record = new_metadata_record(
                **common,
                preview_url=capture.preview_url,
                pdf_url=capture.pdf_url,
                local_path=local_path,
                sha256=validation.sha256,
                file_size=validation.file_size,
                download_status="already_exists",
                duplicate_reason="same_sha256",
            )
            write_status(metadata, stats, record, logger)
            checkpoint.mark_report(
                capture.preview_url, capture.pdf_url, validation.sha256
            )
            return True
        local, created = save_pdf(
            paths,
            match.organization,
            normalized_date,
            row.report_title,
            validation.sha256,
            capture.data,
        )
        status = "downloaded" if created else "already_exists"
        reason = "" if created else "same_target_file_sha256"
        record = new_metadata_record(
            **common,
            preview_url=capture.preview_url,
            pdf_url=capture.pdf_url,
            local_path=relative_path(local, paths.root),
            sha256=validation.sha256,
            file_size=validation.file_size,
            download_status=status,
            duplicate_reason=reason,
        )
        write_status(metadata, stats, record, logger)
        checkpoint.mark_report(capture.preview_url, capture.pdf_url, validation.sha256)
        return True
    except AccessPausedError:
        raise
    except Exception as exc:
        record = new_metadata_record(
            **common,
            download_status="failed",
            error_message=redact_message(exc),
        )
        write_status(metadata, stats, record, logger)
        return False


def next_history_page(page: Any, next_number: int, timeout_ms: int) -> bool:
    pagination = page.locator(".q-pagination")
    if not pagination.count():
        return False
    target = pagination.get_by_text(str(next_number), exact=True)
    if not target.count():
        return False
    old_first = ""
    rows = report_rows(page)
    if rows:
        old_first = f"{rows[0].report_date_raw}|{rows[0].report_title}"
    target.last.click(timeout=timeout_ms)
    deadline = time.monotonic() + timeout_ms / 1000
    while time.monotonic() < deadline:
        page.wait_for_timeout(250)
        current = report_rows(page)
        if (
            not current
            or f"{current[0].report_date_raw}|{current[0].report_title}" != old_first
        ):
            return bool(current)
    raise RuntimeError("报告分页后内容未更新")


def report_count_text(page: Any) -> str:
    locator = page.locator(".q-pagination__total")
    return locator.first.inner_text().strip() if locator.count() else ""


def process_actor(
    page: Any,
    context: Any,
    paths: AppPaths,
    match: MatchedActor,
    start_date: date,
    end_date: date,
    args: argparse.Namespace,
    events: Sequence[EventRecord],
    metadata: MetadataStore,
    checkpoint: CheckpointStore,
    stats: Counter[str],
    methods: Counter[str],
    logger: logging.Logger,
    audit: AuditObservation | None = None,
) -> bool:
    if audit is None and match.actor_detail_url:
        page.goto(
            match.actor_detail_url,
            wait_until="domcontentloaded",
            timeout=args.page_timeout,
        )
        page.get_by_role("tab", name="历史报告", exact=True).wait_for(
            state="visible", timeout=args.page_timeout
        )
        actor_detail_url = page.url
    else:
        goto_apt_page(page, args.page_timeout)
        check_access(page, headed=not args.headless, logger=logger)
        actor_detail_url = open_actor_detail(
            page, match.platform_name, args.page_timeout
        )
    check_access(page, headed=not args.headless, logger=logger)
    open_history_tab(page, args.page_timeout)
    if audit is not None:
        audit.selected_actor = match.platform_name
        audit.actor_detail_url = actor_detail_url
        audit.table_headers = history_headers(page)
        audit.report_count_text = report_count_text(page)
    eligible_attempted = 0
    page_number = 1
    actor_complete = True
    stop_for_cutoff = False
    limited_by_max_reports = False
    while True:
        rows = report_rows(page)
        descending = dates_are_descending(rows) if rows else True
        if audit is not None and page_number == 1:
            audit.first_page_dates = [row.report_date_raw for row in rows]
            audit.descending = descending
        for row in rows:
            parsed = parse_report_date(row.report_date_raw)
            if parsed is None:
                append_manual_review(
                    paths,
                    match,
                    actor_detail_url,
                    row,
                    "missing_or_incomplete_report_date",
                )
                if audit is None:
                    write_status(
                        metadata,
                        stats,
                        new_metadata_record(
                            **base_record(match, actor_detail_url, row),
                            download_status="manual_required",
                            duplicate_reason="missing_or_incomplete_report_date",
                        ),
                        logger,
                    )
                actor_complete = False
                continue
            normalized_date = parsed.isoformat()
            if parsed > end_date:
                if audit is None:
                    write_status(
                        metadata,
                        stats,
                        new_metadata_record(
                            **base_record(
                                match, actor_detail_url, row, normalized_date
                            ),
                            download_status="skipped",
                            duplicate_reason="after_end_date",
                        ),
                        logger,
                    )
                continue
            if parsed < start_date:
                if audit is None:
                    write_status(
                        metadata,
                        stats,
                        new_metadata_record(
                            **base_record(
                                match, actor_detail_url, row, normalized_date
                            ),
                            download_status="skipped",
                            duplicate_reason="before_start_date",
                        ),
                        logger,
                    )
                if descending:
                    stop_for_cutoff = True
                    break
                continue
            if (
                args.max_reports_per_organization
                and eligible_attempted >= args.max_reports_per_organization
            ):
                limited_by_max_reports = True
                stop_for_cutoff = True
                break
            eligible_attempted += 1
            if audit is not None:
                if not audit.preview_url:
                    try:
                        preview, pdf, content_type = audit_report_preview(
                            page, row, actor_detail_url, args.download_timeout
                        )
                        audit.preview_title = row.report_title
                        audit.preview_url = pdf
                        audit.pdf_content_type = content_type or "浏览器内置 PDF 查看器接管响应"
                        audit.pdf_loading_method = (
                            "报告标题按钮打开模态框；模态框中的 iframe[title='Embedded PDF'] "
                            "加载 /alpha-api/v2/apt-dossier/apt-report?name=<报告ID>"
                        )
                    except Exception as exc:
                        audit.notes.append(f"PDF 预览审计失败：{redact_message(exc)}")
                        actor_complete = False
                stop_for_cutoff = True
                break
            succeeded = process_report(
                page,
                context,
                paths,
                match,
                actor_detail_url,
                row,
                normalized_date,
                args,
                events,
                metadata,
                checkpoint,
                stats,
                methods,
                logger,
            )
            actor_complete = actor_complete and succeeded
            check_access(page, headed=not args.headless, logger=logger)
            time.sleep(random.uniform(1, 3))
        if stop_for_cutoff:
            break
        page_number += 1
        if not next_history_page(page, page_number, args.page_timeout):
            break
    if (
        audit is None
        and not args.dry_run
        and actor_complete
        and not limited_by_max_reports
    ):
        checkpoint.mark_organization(match.organization.id)
    return actor_complete


def write_audit(paths: AppPaths, audit: AuditObservation) -> None:
    order = "是" if audit.descending else "否或无法确认"
    dates = "、".join(audit.first_page_dates) if audit.first_page_dates else "未取得"
    notes = "\n".join(f"- {note}" for note in audit.notes) or "- 无额外异常。"
    content = f"""# 奇安信 APT 页面审计

- 审计时间（UTC）：{utc_now_iso()}
- 目标入口：{APT_URL}
- 登录状态：页面公开内容可匿名访问；如账号态内容或验证出现，使用持久化浏览器人工处理。

## 定位与页面结构

- “APT组织画像”入口：按可见文本 `APT组织画像` 精确定位。
- 组织列表：地图上的可聚焦列表项 `main li[tabindex='0']`；本次观察到 {audit.actor_count} 个唯一可见组织；未发现组织级分页。
- 组织详情入口：按经过 CSV 规则匹配后的平台组织可见文本精确定位。
- 本次详情组织：{audit.selected_actor or '未打开'}。
- 详情 URL：{audit.actor_detail_url or '未取得'}。
- “历史报告”栏目：`role=tab` 且可见名称为 `历史报告`。
- 报告表头：{'、'.join(audit.table_headers) if audit.table_headers else '未取得'}。
- 报告数量/分页：{audit.report_count_text or '未观察到分页总数'}；页码位于 `.q-pagination`，按精确页码文本点击。
- 首页报告日期：{dates}。
- 首页是否按日期倒序：{order}。

## PDF 预览与原始文件

- 审计报告：{audit.preview_title or '日期范围内未发现可审计报告，未打开旧报告'}。
- 预览/稳定 PDF 地址：{audit.preview_url or '未取得'}。
- 打开方式：{audit.pdf_loading_method}。
- 内容类型：{audit.pdf_content_type or '未取得'}。
- 下载器优先级：正常下载事件 → `application/pdf` 网络响应 → `.pdf` URL → iframe/embed/object 原始地址 → Blob 背后的 PDF 响应。
- 认证处理：文件请求通过同一个 Playwright 浏览器上下文发起；不会输出 Cookie、Token、认证头或带签名查询参数的 URL。

## 其他观察

{notes}
"""
    paths.page_audit.write_text(content, encoding="utf-8")


def login_only(page: Any, args: argparse.Namespace, logger: logging.Logger) -> int:
    goto_apt_page(page, args.page_timeout)
    logger.info("浏览器会话目录已就绪。请在浏览器中自行完成登录或验证码。")
    if not sys.stdin.isatty():
        logger.error("当前终端不可交互，无法等待人工登录")
        return 2
    input("完成登录/验证后按 Enter 保存会话并关闭浏览器：")
    logger.info("已关闭持久化上下文；登录状态保存在 data/state/browser-profile")
    return 0


def run(args: argparse.Namespace, start_date: date, end_date: date) -> int:
    paths = AppPaths.from_root(PROJECT_ROOT)
    paths.ensure_directories()
    logger = configure_logging(paths)
    ensure_reference_files(paths)
    organizations = load_organizations(paths.organizations_csv)
    events = load_events(paths.events_csv)
    selected = select_organizations(organizations, args)
    metadata = MetadataStore(paths.reports_jsonl, paths.reports_csv)
    checkpoint = CheckpointStore(paths.checkpoint)
    stats: Counter[str] = Counter()
    methods: Counter[str] = Counter()
    logger.info(
        "启动：mode=%s date=%s..%s selected_orgs=%d dry_run=%s",
        args.mode,
        start_date,
        end_date,
        len(selected),
        args.dry_run,
    )

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        logger.error("缺少 Playwright；请安装 requirements.txt")
        return 2

    with sync_playwright() as playwright:
        context = launch_persistent_context(playwright, paths, args, logger)
        try:
            page = context.pages[0] if context.pages else context.new_page()
            page.set_default_timeout(args.page_timeout)
            page.set_default_navigation_timeout(args.page_timeout)
            if args.login_only:
                return login_only(page, args, logger)
            goto_apt_page(page, args.page_timeout)
            check_access(page, headed=not args.headless, logger=logger)
            actor_names = platform_actor_names(page)
            detail_urls = platform_actor_detail_urls(context, args.page_timeout)
            matching_actor_names = list(actor_names)
            if args.mode != "audit":
                # Some directory entries have valid platform detail routes but are
                # omitted from the current map visualization. They remain eligible
                # only when the same strict CSV matching tiers succeed.
                matching_actor_names.extend(
                    name for name in detail_urls if name not in set(actor_names)
                )
            matches, unmatched = match_selected_actors(
                matching_actor_names, organizations, selected, detail_urls
            )
            if unmatched:
                record_unmatched(
                    paths, unmatched, "not_present_in_visible_platform_actor_list"
                )
                logger.warning("%d 个 CSV 组织未与可见平台组织精确匹配", len(unmatched))
            if args.resume and args.mode == "backfill":
                matches = [
                    match
                    for match in matches
                    if match.organization.id not in checkpoint.completed_organizations
                ]
            limit = args.max_organizations
            if args.mode == "audit" and limit is None:
                limit = 1
            if limit is not None:
                matches = matches[:limit]
            if not matches:
                logger.warning("没有待处理的匹配组织")
                return 0
            audit = (
                AuditObservation(actor_count=len(actor_names))
                if args.mode == "audit"
                else None
            )
            for index, match in enumerate(matches, 1):
                logger.info(
                    "处理组织 %s/%s：%s -> %s（%s）",
                    index,
                    len(matches),
                    match.organization.name,
                    match.platform_name,
                    match.match_method,
                )
                for attempt in (1, 2):
                    try:
                        process_actor(
                            page,
                            context,
                            paths,
                            match,
                            start_date,
                            end_date,
                            args,
                            events,
                            metadata,
                            checkpoint,
                            stats,
                            methods,
                            logger,
                            audit,
                        )
                        break
                    except AccessPausedError:
                        raise
                    except Exception as exc:
                        if attempt == 1:
                            logger.warning(
                                "组织 %s 页面处理异常，将重建页面后重试一次：%s",
                                match.organization.id,
                                redact_message(exc),
                            )
                            try:
                                page.close()
                            except Exception:
                                pass
                            page = context.new_page()
                            page.set_default_timeout(args.page_timeout)
                            page.set_default_navigation_timeout(args.page_timeout)
                            time.sleep(5)
                            continue
                        stats["failed"] += 1
                        logger.error(
                            "组织 %s 两次处理均失败：%s",
                            match.organization.id,
                            redact_message(exc),
                        )
                if index < len(matches):
                    time.sleep(random.uniform(2, 5))
            if audit is not None:
                write_audit(paths, audit)
                logger.info("页面审计已写入 %s", relative_path(paths.page_audit, paths.root))
        except AccessPausedError as exc:
            logger.error("任务暂停：%s", exc)
            return 3
        finally:
            context.close()
    logger.info(
        "汇总 downloaded=%d already_exists=%d duplicate_event=%d skipped=%d failed=%d manual_required=%d",
        stats["downloaded"],
        stats["already_exists"],
        stats["duplicate_event"],
        stats["skipped"],
        stats["failed"],
        stats["manual_required"],
    )
    if methods:
        logger.info(
            "PDF 捕获方式统计：%s",
            ", ".join(f"{key}={value}" for key, value in methods.items()),
        )
    return 1 if stats["failed"] else 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    start_date, end_date = validate_args(parser, args)
    try:
        return run(args, start_date, end_date)
    except KeyboardInterrupt:
        print("\n用户中断；已完成的元数据和检查点已保留。", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"错误：{redact_message(exc)}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
