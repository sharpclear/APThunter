from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import re
import unicodedata
from dataclasses import asdict, dataclass, fields
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Iterable, Mapping, Sequence
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


METADATA_FIELDS = [
    "organization_id",
    "organization_name",
    "platform_actor_name",
    "actor_detail_url",
    "report_title",
    "report_date",
    "preview_url",
    "pdf_url",
    "local_path",
    "sha256",
    "file_size",
    "download_status",
    "duplicate_reason",
    "error_message",
    "collected_at",
]

VALID_STATUSES = {
    "downloaded",
    "already_exists",
    "duplicate_event",
    "manual_required",
    "failed",
    "skipped",
}

TRANSIENT_QUERY_KEYS = {
    "expires",
    "signature",
    "token",
    "x-amz-algorithm",
    "x-amz-checksum-mode",
    "x-amz-credential",
    "x-amz-date",
    "x-amz-expires",
    "x-amz-security-token",
    "x-amz-signature",
    "x-amz-signedheaders",
    "x-id",
}

MISSING_PUBLISHER_MARKERS = {
    "-",
    "--",
    "—",
    "–",
    "n/a",
    "na",
    "none",
    "null",
    "unknown",
    "未知",
    "暂无",
    "无",
}


@dataclass(frozen=True)
class Organization:
    id: str
    name: str
    aliases: tuple[str, ...]


@dataclass(frozen=True)
class PlatformActor:
    name: str


@dataclass(frozen=True)
class EventRecord:
    organization_id: str
    event_date: str
    title: str
    link: str


@dataclass
class MetadataRecord:
    organization_id: str = ""
    organization_name: str = ""
    platform_actor_name: str = ""
    actor_detail_url: str = ""
    report_title: str = ""
    report_publisher: str = ""
    report_date: str = ""
    preview_url: str = ""
    pdf_url: str = ""
    local_path: str = ""
    sha256: str = ""
    file_size: int = 0
    download_status: str = "failed"
    duplicate_reason: str = ""
    error_message: str = ""
    collected_at: str = ""

    def as_dict(self) -> dict[str, object]:
        row = asdict(self)
        value = {name: row[name] for name in METADATA_FIELDS}
        # JSONL 是规范元数据源；保留旧 CSV 表头兼容已有文件。
        value["report_publisher"] = row["report_publisher"]
        return value


@dataclass(frozen=True)
class DuplicateDecision:
    status: str
    reason: str


@dataclass(frozen=True)
class PdfValidation:
    sha256: str
    file_size: int
    page_count: int | None


def utc_now_iso() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def split_aliases(raw: str | None) -> tuple[str, ...]:
    if not raw:
        return ()
    value = raw.strip()
    if not value:
        return ()
    if value.startswith("["):
        try:
            parsed = json.loads(value)
            if isinstance(parsed, list):
                return tuple(str(item).strip() for item in parsed if str(item).strip())
        except json.JSONDecodeError:
            pass
    return tuple(
        part.strip() for part in re.split(r"\s*[|;；]\s*", value) if part.strip()
    )


def load_organizations(path: Path) -> list[Organization]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        required = {"id", "name", "aliases"}
        missing = required - set(reader.fieldnames or ())
        if missing:
            raise ValueError(
                f"apt_organizations.csv 缺少字段: {', '.join(sorted(missing))}"
            )
        organizations = []
        for row in reader:
            org_id = (row.get("id") or "").strip()
            name = (row.get("name") or "").strip()
            if not org_id or not name:
                continue
            organizations.append(
                Organization(org_id, name, split_aliases(row.get("aliases")))
            )
    return organizations


def load_events(path: Path) -> list[EventRecord]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        required = {"event_date", "title", "organization_id", "link"}
        missing = required - set(reader.fieldnames or ())
        if missing:
            raise ValueError(f"apt_events.csv 缺少字段: {', '.join(sorted(missing))}")
        return [
            EventRecord(
                organization_id=(row.get("organization_id") or "").strip(),
                event_date=(row.get("event_date") or "").strip(),
                title=(row.get("title") or "").strip(),
                link=(row.get("link") or "").strip(),
            )
            for row in reader
        ]


def normalize_actor_name(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value).casefold()
    return re.sub(r"[\s\-_‐‑‒–—―]+", "", normalized)


def normalize_title(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value).casefold().strip()
    return re.sub(r"\s+", " ", normalized)


def normalize_report_publisher(value: object) -> str:
    publisher = str(value or "").strip()
    if publisher.casefold() in MISSING_PUBLISHER_MARKERS:
        return ""
    return publisher


def compact_title(value: str) -> str:
    return re.sub(r"[^0-9a-z\u4e00-\u9fff]+", "", normalize_title(value))


def match_platform_actor(
    platform_name: str, organizations: Sequence[Organization]
) -> tuple[Organization | None, str]:
    tiers: list[tuple[str, list[Organization]]] = [
        ("exact_name", [org for org in organizations if platform_name == org.name]),
        (
            "exact_alias",
            [
                org
                for org in organizations
                if any(platform_name == alias for alias in org.aliases)
            ],
        ),
    ]
    normalized = normalize_actor_name(platform_name)
    tiers.append(
        (
            "normalized_name_or_alias",
            [
                org
                for org in organizations
                if normalized == normalize_actor_name(org.name)
                or any(
                    normalized == normalize_actor_name(alias) for alias in org.aliases
                )
            ],
        )
    )
    for tier, matches in tiers:
        unique = {org.id: org for org in matches}
        if len(unique) == 1:
            return next(iter(unique.values())), tier
        if len(unique) > 1:
            return None, f"ambiguous_{tier}"
    return None, "no_exact_match"


FULL_DATE_PATTERNS = (
    re.compile(r"^(\d{4})-(\d{1,2})-(\d{1,2})(?:[T\s].*)?$"),
    re.compile(r"^(\d{4})/(\d{1,2})/(\d{1,2})(?:[T\s].*)?$"),
    re.compile(r"^(\d{4})年(\d{1,2})月(\d{1,2})日?$"),
)


def parse_report_date(value: str | None) -> date | None:
    if not value:
        return None
    text = unicodedata.normalize("NFKC", value).strip()
    for pattern in FULL_DATE_PATTERNS:
        match = pattern.fullmatch(text)
        if not match:
            continue
        try:
            return date(*(int(part) for part in match.groups()))
        except ValueError:
            return None
    return None


def parse_cli_date(value: str, *, today: date | None = None) -> date:
    if value.casefold() == "today":
        return today or date.today()
    parsed = parse_report_date(value)
    if parsed is None:
        raise ValueError("日期必须是完整的 YYYY-MM-DD，或使用 today")
    return parsed


def normalize_url(value: str | None, *, strip_transient: bool = True) -> str:
    if not value:
        return ""
    text = value.strip()
    try:
        parts = urlsplit(text)
    except ValueError:
        return text
    if not parts.scheme and not parts.netloc:
        return text.rstrip("/")
    host = (parts.hostname or "").casefold()
    if parts.port and not (
        (parts.scheme.casefold() == "http" and parts.port == 80)
        or (parts.scheme.casefold() == "https" and parts.port == 443)
    ):
        host = f"{host}:{parts.port}"
    query_items = []
    for key, item_value in parse_qsl(parts.query, keep_blank_values=True):
        lowered = key.casefold()
        if strip_transient and (
            lowered in TRANSIENT_QUERY_KEYS or lowered.startswith("utm_")
        ):
            continue
        query_items.append((key, item_value))
    query_items.sort(key=lambda item: (item[0].casefold(), item[1]))
    path = re.sub(r"/{2,}", "/", parts.path or "/")
    if path != "/":
        path = path.rstrip("/")
    return urlunsplit(
        (parts.scheme.casefold(), host, path, urlencode(query_items, doseq=True), "")
    )


def safe_url_for_storage(value: str | None) -> str:
    return normalize_url(value, strip_transient=True)


def event_duplicate_decision(
    organization_id: str,
    report_date: str,
    report_title: str,
    candidate_urls: Iterable[str],
    events: Sequence[EventRecord],
) -> DuplicateDecision | None:
    title = normalize_title(report_title)
    compact = compact_title(report_title)
    urls = {normalize_url(url) for url in candidate_urls if normalize_url(url)}
    possible = False
    for event in events:
        event_url = normalize_url(event.link)
        if event_url and event_url in urls:
            return DuplicateDecision("duplicate_event", "same_normalized_source_url")
        if event.organization_id != organization_id or event.event_date != report_date:
            continue
        event_title = normalize_title(event.title)
        if title and title == event_title:
            return DuplicateDecision("duplicate_event", "same_organization_date_title")
        event_compact = compact_title(event.title)
        if compact and event_compact and min(len(compact), len(event_compact)) >= 8:
            if compact in event_compact or event_compact in compact:
                possible = True
    if possible:
        return DuplicateDecision(
            "manual_required", "possible_duplicate_similar_title_same_date"
        )
    return None


def sanitize_filename(
    value: str, *, max_length: int = 100, fallback: str = "untitled"
) -> str:
    text = unicodedata.normalize("NFKC", value)
    text = re.sub(r"[<>:\"/\\|?*\x00-\x1f]", "_", text)
    text = re.sub(r"\s+", " ", text).strip(" .")
    if not text:
        text = fallback
    reserved = {"CON", "PRN", "AUX", "NUL"} | {
        f"{prefix}{number}" for prefix in ("COM", "LPT") for number in range(1, 10)
    }
    if text.upper() in reserved:
        text = f"_{text}"
    return text[:max_length].rstrip(" .") or fallback


def validate_pdf(data: bytes) -> PdfValidation:
    if not data:
        raise ValueError("PDF 文件为空")
    if not data.startswith(b"%PDF-"):
        prefix = data[:256].lstrip().lower()
        if prefix.startswith((b"<!doctype html", b"<html", b"<script")):
            raise ValueError("响应是 HTML 页面，不是原始 PDF")
        raise ValueError("文件缺少 %PDF- 文件头")
    try:
        from pypdf import PdfReader
    except ImportError as exc:
        raise RuntimeError("缺少 pypdf；请先安装 requirements.txt") from exc
    try:
        reader = PdfReader(io.BytesIO(data), strict=False)
        page_count: int | None = len(reader.pages)
    except Exception as exc:
        raise ValueError(f"基础 PDF 解析失败: {type(exc).__name__}") from exc
    return PdfValidation(
        sha256=hashlib.sha256(data).hexdigest(),
        file_size=len(data),
        page_count=page_count,
    )


def load_jsonl(path: Path) -> list[dict[str, object]]:
    if not path.exists():
        return []
    rows: list[dict[str, object]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path.name} 第 {line_number} 行不是有效 JSON") from exc
            if isinstance(value, dict):
                rows.append(value)
    return rows


class MetadataStore:
    def __init__(self, jsonl_path: Path, csv_path: Path):
        self.jsonl_path = jsonl_path
        self.csv_path = csv_path
        self.rows = load_jsonl(jsonl_path)
        self.successful_triples: set[tuple[str, str, str]] = set()
        self.preview_urls: set[str] = set()
        self.pdf_urls: set[str] = set()
        self.sha256s: set[str] = set()
        for row in self.rows:
            status = str(row.get("download_status", ""))
            if status not in {"downloaded", "already_exists", "duplicate_event"}:
                continue
            org_id = str(row.get("organization_id", ""))
            report_date = str(row.get("report_date", ""))
            title = normalize_title(str(row.get("report_title", "")))
            if org_id and report_date and title:
                self.successful_triples.add((org_id, title, report_date))
            preview = normalize_url(str(row.get("preview_url", "")))
            pdf = normalize_url(str(row.get("pdf_url", "")))
            sha = str(row.get("sha256", "")).casefold()
            if preview:
                self.preview_urls.add(preview)
            if pdf:
                self.pdf_urls.add(pdf)
            if sha:
                self.sha256s.add(sha)

    def preflight_duplicate(
        self,
        organization_id: str,
        title: str,
        report_date: str,
        preview_url: str = "",
        pdf_url: str = "",
    ) -> DuplicateDecision | None:
        triple = (organization_id, normalize_title(title), report_date)
        if triple in self.successful_triples:
            return DuplicateDecision("already_exists", "same_organization_title_date")
        preview = normalize_url(preview_url)
        pdf = normalize_url(pdf_url)
        if preview and preview in self.preview_urls:
            return DuplicateDecision("already_exists", "processed_preview_url")
        if pdf and pdf in self.pdf_urls:
            return DuplicateDecision("already_exists", "processed_pdf_url")
        return None

    def append(self, record: MetadataRecord) -> None:
        if record.download_status not in VALID_STATUSES:
            raise ValueError(f"无效 download_status: {record.download_status}")
        row = record.as_dict()
        self.jsonl_path.parent.mkdir(parents=True, exist_ok=True)
        with self.jsonl_path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=False) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        write_header = not self.csv_path.exists() or self.csv_path.stat().st_size == 0
        with self.csv_path.open("a", encoding="utf-8-sig", newline="") as handle:
            writer = csv.DictWriter(
                handle, fieldnames=METADATA_FIELDS, extrasaction="ignore"
            )
            if write_header:
                writer.writeheader()
            writer.writerow(row)
            handle.flush()
            os.fsync(handle.fileno())
        self.rows.append(row)
        if record.download_status in {
            "downloaded",
            "already_exists",
            "duplicate_event",
        }:
            title = normalize_title(record.report_title)
            if record.organization_id and record.report_date and title:
                self.successful_triples.add(
                    (record.organization_id, title, record.report_date)
                )
            if record.preview_url:
                self.preview_urls.add(normalize_url(record.preview_url))
            if record.pdf_url:
                self.pdf_urls.add(normalize_url(record.pdf_url))
            if record.sha256:
                self.sha256s.add(record.sha256.casefold())


class CheckpointStore:
    VERSION = 1

    def __init__(self, path: Path):
        self.path = path
        self.data: dict[str, object] = {
            "version": self.VERSION,
            "completed_organizations": [],
            "processed_report_urls": [],
            "processed_pdf_urls": [],
            "sha256": [],
            "updated_at": "",
        }
        if path.exists():
            loaded = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(loaded, dict):
                raise ValueError("qianxin-checkpoint.json 必须是 JSON 对象")
            self.data.update(loaded)
        self.completed_organizations = {
            str(item) for item in self.data.get("completed_organizations", [])
        }
        self.processed_report_urls = {
            normalize_url(str(item))
            for item in self.data.get("processed_report_urls", [])
            if item
        }
        self.processed_pdf_urls = {
            normalize_url(str(item))
            for item in self.data.get("processed_pdf_urls", [])
            if item
        }
        self.sha256s = {
            str(item).casefold() for item in self.data.get("sha256", []) if item
        }

    def is_processed_url(self, preview_url: str = "", pdf_url: str = "") -> bool:
        preview = normalize_url(preview_url)
        pdf = normalize_url(pdf_url)
        return bool(
            (preview and preview in self.processed_report_urls)
            or (pdf and pdf in self.processed_pdf_urls)
        )

    def mark_report(
        self, preview_url: str = "", pdf_url: str = "", sha256: str = ""
    ) -> None:
        if preview_url:
            self.processed_report_urls.add(normalize_url(preview_url))
        if pdf_url:
            self.processed_pdf_urls.add(normalize_url(pdf_url))
        if sha256:
            self.sha256s.add(sha256.casefold())
        self.save()

    def mark_organization(self, organization_id: str) -> None:
        self.completed_organizations.add(str(organization_id))
        self.save()

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": self.VERSION,
            "completed_organizations": sorted(self.completed_organizations),
            "processed_report_urls": sorted(filter(None, self.processed_report_urls)),
            "processed_pdf_urls": sorted(filter(None, self.processed_pdf_urls)),
            "sha256": sorted(filter(None, self.sha256s)),
            "updated_at": utc_now_iso(),
        }
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        temporary.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        os.replace(temporary, self.path)


def append_review_csv(
    path: Path, fieldnames: Sequence[str], row: Mapping[str, object]
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    write_header = not path.exists() or path.stat().st_size == 0
    with path.open("a", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        if write_header:
            writer.writeheader()
        writer.writerow({name: row.get(name, "") for name in fieldnames})


def new_metadata_record(**values: object) -> MetadataRecord:
    allowed = {field.name for field in fields(MetadataRecord)}
    filtered = {key: value for key, value in values.items() if key in allowed}
    if not filtered.get("collected_at"):
        filtered["collected_at"] = utc_now_iso()
    return MetadataRecord(**filtered)  # type: ignore[arg-type]
