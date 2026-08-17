from __future__ import annotations

import hashlib
import html
import re
import xml.etree.ElementTree as ET
from datetime import datetime
from email.utils import parsedate_to_datetime
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup, Tag

from .models import OriginalSource, ParseError, ReportRecord, ReportSeed


DATE_DAY_RE = re.compile(r"(?<!\d)(\d{4})[-/](\d{1,2})[-/](\d{1,2})(?!\d)")
DATE_MONTH_RE = re.compile(r"(?<!\d)(\d{4})[-/](\d{1,2})(?![-/\d])")
DATE_YEAR_RE = re.compile(r"(?<!\d)(20\d{2})(?!\d)")
SOURCE_RE = re.compile(
    r"\|\s*Source:\s*(https?://\S+?)(?:\s+\(([^()]*)\))?"
    r"(?=\s*\|\s*Tags:|$)",
    re.IGNORECASE,
)
TAGS_RE = re.compile(r"\|\s*Tags:\s*(.*)$", re.IGNORECASE | re.DOTALL)
REPORT_PATH_RE = re.compile(r"^/reports/[^/?#]+/$")


def parse_partial_date(value: str) -> tuple[str, str]:
    cleaned = " ".join(value.split())
    match = DATE_DAY_RE.search(cleaned)
    if match:
        year, month, day = (int(part) for part in match.groups())
        try:
            parsed = datetime(year, month, day)
        except ValueError as exc:
            raise ParseError(f"无效日期：{match.group(0)}") from exc
        return parsed.date().isoformat(), "day"
    match = DATE_MONTH_RE.search(cleaned)
    if match:
        year, month = (int(part) for part in match.groups())
        if not 1 <= month <= 12:
            raise ParseError(f"无效月份：{match.group(0)}")
        return f"{year:04d}-{month:02d}", "month"
    match = DATE_YEAR_RE.search(cleaned)
    if match:
        return match.group(1), "year"
    raise ParseError(f"未找到可识别日期：{cleaned[:120]}")


def parse_rss(xml_text: str) -> list[ReportSeed]:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise ParseError(f"RSS XML 无法解析：{exc}") from exc
    items = root.findall(".//item")
    if not items:
        raise ParseError("RSS 中没有 item")
    seeds: list[ReportSeed] = []
    seen: set[str] = set()
    for item in items:
        title = _element_text(item.find("title"))
        link = _element_text(item.find("link")) or _element_text(item.find("guid"))
        pub_date = _element_text(item.find("pubDate"))
        creator = ""
        for child in item:
            if child.tag.endswith("creator"):
                creator = _element_text(child)
                break
        description = html.unescape(_element_text(item.find("description")))
        if not title or not link or not pub_date:
            raise ParseError("RSS item 缺少 title、link 或 pubDate")
        try:
            parsed_date = parsedate_to_datetime(pub_date)
        except (TypeError, ValueError, OverflowError) as exc:
            raise ParseError(f"RSS pubDate 无法解析：{pub_date}") from exc
        original_url, source_publisher, summary, tags = _parse_rss_description(
            description
        )
        if link in seen:
            continue
        seen.add(link)
        seeds.append(
            ReportSeed(
                detail_url=link.strip(),
                title=title,
                published_date=parsed_date.date().isoformat(),
                date_precision="day",
                publisher=source_publisher or creator,
                summary=summary,
                original_url=original_url,
                tags=tuple(tags),
                discovery_source="rss",
            )
        )
    return seeds


def parse_report_list(html_text: str, base_url: str) -> list[ReportSeed]:
    soup = BeautifulSoup(html_text, "html.parser")
    cards = soup.select(".timeline-item")
    seeds: list[ReportSeed] = []
    seen: set[str] = set()
    if cards:
        for card in cards:
            seed = _parse_timeline_card(card, base_url)
            if seed and seed.detail_url not in seen:
                seen.add(seed.detail_url)
                seeds.append(seed)
    else:
        for anchor in soup.select("h3 a[href], h4 a[href], article a[href]"):
            href = anchor.get("href", "")
            if not _is_report_detail_path(href):
                continue
            container = anchor.find_parent(["article", "li", "div"]) or anchor.parent
            if not isinstance(container, Tag):
                continue
            try:
                published_date, precision = parse_partial_date(
                    container.get_text(" ", strip=True)
                )
            except ParseError:
                continue
            detail_url = urljoin(base_url, href)
            if detail_url in seen:
                continue
            seen.add(detail_url)
            publisher_anchor = container.select_one('a[href*="/authors/"]')
            publisher = (
                publisher_anchor.get_text(" ", strip=True)
                if publisher_anchor
                else ""
            )
            tags = tuple(
                value
                for value in (
                    tag.get_text(" ", strip=True).lstrip("#")
                    for tag in container.select('a[href*="/tags/"]')
                )
                if value
            )
            seeds.append(
                ReportSeed(
                    detail_url=detail_url,
                    title=anchor.get_text(" ", strip=True),
                    published_date=published_date,
                    date_precision=precision,
                    publisher=publisher,
                    tags=tags,
                    discovery_source="reports-list",
                )
            )
    if not seeds:
        raise ParseError("Reports 列表页未找到可识别的报告卡片")
    return seeds


def parse_report_detail(
    html_text: str,
    *,
    seed: ReportSeed,
    requested_url: str,
    final_url: str,
    http_status: int,
    content_sha256: str,
    fetched_at: str,
) -> ReportRecord:
    soup = BeautifulSoup(html_text, "html.parser")
    main = soup.find("main") or soup
    header = (
        main.select_one("section hgroup")
        or main.select_one("article hgroup")
        or main.find("hgroup")
    )
    title_node = (
        header.find(["h1", "h2"]) if isinstance(header, Tag) else None
    )
    if title_node is None:
        title_node = main.select_one("h1, h2")
    title = (
        title_node.get_text(" ", strip=True) if title_node is not None else ""
    ) or seed.title
    if not title:
        raise ParseError("报告详情页缺少标题")

    header_text = header.get_text(" ", strip=True) if isinstance(header, Tag) else ""
    date_source = header_text or seed.published_date
    try:
        published_date, date_precision = parse_partial_date(date_source)
    except ParseError:
        if seed.published_date:
            published_date = seed.published_date
            date_precision = seed.date_precision
        else:
            raise ParseError("报告详情页缺少发布日期")

    publisher_anchor = (
        header.select_one('a[href*="/authors/"]')
        if isinstance(header, Tag)
        else None
    )
    publisher = (
        publisher_anchor.get_text(" ", strip=True)
        if publisher_anchor is not None
        else seed.publisher
    )
    original_url = _find_original_url(header, final_url) or seed.original_url
    tags = _extract_tags(main) or seed.tags
    summary = _extract_summary(main, header) or seed.summary
    related_actors = _extract_related_actors(main)
    warnings: list[str] = []
    if not original_url:
        warnings.append("详情页未提供原始来源 URL")
    if not related_actors:
        warnings.append("详情页未提供 Related Actors")
    if not summary:
        warnings.append("详情页未提供摘要")

    return ReportRecord(
        source_record_id=source_record_id_from_url(
            final_url, content_sha256=content_sha256
        ),
        lazarus_day_url=final_url,
        requested_url=requested_url,
        title=title,
        published_date=published_date,
        date_precision=date_precision,
        publisher=publisher,
        original_url=original_url,
        summary=summary,
        tags=tuple(tags),
        related_actors=tuple(related_actors),
        http_status=http_status,
        final_url=final_url,
        content_sha256=content_sha256,
        fetched_at=fetched_at,
        raw_html=html_text,
        parse_warnings=tuple(warnings),
    )


def parse_original_source(
    html_text: str,
    *,
    requested_url: str,
    final_url: str,
    http_status: int,
    content_sha256: str,
    fetched_at: str,
    source_level: str,
) -> OriginalSource:
    soup = BeautifulSoup(html_text, "html.parser")
    title = _meta_content(soup, "property", "og:title")
    if not title and soup.title:
        title = soup.title.get_text(" ", strip=True)
    summary = (
        _meta_content(soup, "property", "og:description")
        or _meta_content(soup, "name", "description")
    )
    published: str | None = None
    date_candidates = [
        _meta_content(soup, "property", "article:published_time"),
        _meta_content(soup, "name", "date"),
        _meta_content(soup, "name", "pubdate"),
    ]
    time_node = soup.find("time")
    if time_node is not None:
        date_candidates.append(time_node.get("datetime", ""))
        date_candidates.append(time_node.get_text(" ", strip=True))
    for candidate in date_candidates:
        if not candidate:
            continue
        try:
            parsed, precision = parse_partial_date(candidate)
        except ParseError:
            continue
        if precision == "day":
            published = parsed
            break
    return OriginalSource(
        requested_url=requested_url,
        final_url=final_url,
        http_status=http_status,
        content_sha256=content_sha256,
        fetched_at=fetched_at,
        title=title,
        published_date=published,
        summary=summary,
        source_level=source_level,
        raw_html=html_text,
    )


def _parse_timeline_card(card: Tag, base_url: str) -> ReportSeed | None:
    anchor = card.select_one("h3 a[href], h4 a[href]")
    if anchor is None:
        return None
    href = anchor.get("href", "")
    if not _is_report_detail_path(href):
        return None
    try:
        published_date, precision = parse_partial_date(
            card.get_text(" ", strip=True)
        )
    except ParseError:
        return None
    publisher_anchor = card.select_one('a[href*="/authors/"]')
    tags = tuple(
        value
        for value in (
            tag.get_text(" ", strip=True).lstrip("#")
            for tag in card.select('a[href*="/tags/"]')
        )
        if value
    )
    return ReportSeed(
        detail_url=urljoin(base_url, href),
        title=anchor.get_text(" ", strip=True),
        published_date=published_date,
        date_precision=precision,
        publisher=(
            publisher_anchor.get_text(" ", strip=True)
            if publisher_anchor is not None
            else ""
        ),
        tags=tags,
        discovery_source="reports-list",
    )


def _parse_rss_description(
    description: str,
) -> tuple[str | None, str, str, list[str]]:
    source_match = SOURCE_RE.search(description)
    tags_match = TAGS_RE.search(description)
    original_url = source_match.group(1).strip() if source_match else None
    publisher = (
        source_match.group(2).strip()
        if source_match and source_match.group(2)
        else ""
    )
    split_at = description.find(" | Source:")
    summary = description[:split_at].strip() if split_at >= 0 else description.strip()
    tags = []
    if tags_match:
        tags = [
            value.strip().lstrip("#")
            for value in tags_match.group(1).split(",")
            if value.strip()
        ]
    return original_url, publisher, summary, tags


def _find_original_url(header: Tag | None, detail_url: str) -> str | None:
    if not isinstance(header, Tag):
        return None
    detail_host = urlsplit(detail_url).hostname
    preferred = header.select_one('a.secondary[href^="http"]')
    anchors = [preferred] if preferred is not None else []
    anchors.extend(header.select('a[href^="http"]'))
    for anchor in anchors:
        if anchor is None:
            continue
        href = anchor.get("href", "").strip()
        if href and urlsplit(href).hostname != detail_host:
            return href
    return None


def _extract_tags(main: Tag) -> tuple[str, ...]:
    nodes = main.select('#tags-display a[href], a[href*="/tags/"]')
    values: list[str] = []
    for node in nodes:
        value = node.get_text(" ", strip=True).lstrip("#")
        if value and value not in values:
            values.append(value)
    return tuple(values)


def _extract_summary(main: Tag, header: Tag | None) -> str:
    header_section = (
        header.find_parent("section") if isinstance(header, Tag) else None
    )
    if isinstance(header_section, Tag):
        sibling = header_section.find_next_sibling("section")
        while isinstance(sibling, Tag):
            if sibling.find(["h2", "h3"]) is None:
                paragraph = sibling.find("p")
                if paragraph:
                    value = paragraph.get_text(" ", strip=True)
                    if value:
                        return value
            sibling = sibling.find_next_sibling("section")
    meta = main.find("meta", attrs={"name": "description"})
    if meta:
        return str(meta.get("content", "")).strip()
    return ""


def _extract_related_actors(main: Tag) -> tuple[str, ...]:
    for heading in main.find_all(["h2", "h3"]):
        if heading.get_text(" ", strip=True).casefold() != "related actors":
            continue
        section = heading.find_parent("section") or heading.parent
        values: list[str] = []
        for node in section.select('h4 a[href*="/actors/"], a[href*="/actors/"]'):
            value = node.get_text(" ", strip=True)
            if value and value not in values:
                values.append(value)
        return tuple(values)
    return ()


def _meta_content(soup: BeautifulSoup, key: str, value: str) -> str:
    node = soup.find("meta", attrs={key: value})
    return str(node.get("content", "")).strip() if node else ""


def source_record_id_from_url(
    url: str, *, content_sha256: str | None = None
) -> str:
    slug = urlsplit(url).path.rstrip("/").rsplit("/", 1)[-1]
    if slug:
        return slug
    if content_sha256 and re.fullmatch(r"[0-9a-fA-F]{64}", content_sha256):
        return content_sha256.lower()
    # Failed fetches have no content to hash. Keep their retry identity stable
    # using the complete URL digest; parsed event records prefer content SHA.
    return hashlib.sha256(url.encode("utf-8")).hexdigest()


def _is_report_detail_path(href: str) -> bool:
    path = urlsplit(href).path
    return bool(REPORT_PATH_RE.match(path)) and not path.endswith("/feed/")


def _element_text(element: ET.Element | None) -> str:
    return (element.text or "").strip() if element is not None else ""
