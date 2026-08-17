from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from typing import Any


COLLECTOR_VERSION = "1.1.0"

REQUIRED_EVENT_FIELDS = (
    "schema_version",
    "record_type",
    "db_id",
    "event_date",
    "date_precision",
    "title",
    "description",
    "threat_type",
    "organization_id",
    "organization_name",
    "releasing_product",
    "link",
    "confidence",
    "review_status",
    "evidence",
    "collection_notes",
    "collected_at",
)

FORBIDDEN_EVENT_FIELDS = {
    "event_type",
    "severity",
    "region",
    "latitude",
    "longitude",
    "created_at",
}

THREAT_TYPES = {
    "钓鱼攻击",
    "C2通信",
    "漏洞利用",
    "恶意软件",
    "凭证窃取",
    "供应链攻击",
    "勒索软件",
    "APT攻击",
    "其他",
}


class CollectorError(RuntimeError):
    """Base error for a collector run."""


class CollectorLockError(CollectorError):
    """Another collector process owns the exclusive lock."""


class FetchError(CollectorError):
    """A URL could not be fetched safely."""


class RobotsDeniedError(FetchError):
    """robots.txt denied a requested URL."""


class ParseError(CollectorError):
    """A source document did not contain the required semantic fields."""


class ValidationError(CollectorError):
    """A normalized record failed schema validation."""


@dataclass(frozen=True)
class FetchResult:
    requested_url: str
    final_url: str
    status_code: int
    body: str
    content_sha256: str
    fetched_at: str
    content_type: str = ""
    headers: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class ReportSeed:
    detail_url: str
    title: str
    published_date: str
    date_precision: str = "day"
    publisher: str = ""
    summary: str = ""
    original_url: str | None = None
    tags: tuple[str, ...] = ()
    discovery_source: str = "rss"


@dataclass(frozen=True)
class ReportRecord:
    source_record_id: str
    lazarus_day_url: str
    requested_url: str
    title: str
    published_date: str
    date_precision: str
    publisher: str
    original_url: str | None
    summary: str
    tags: tuple[str, ...]
    related_actors: tuple[str, ...]
    http_status: int
    final_url: str
    content_sha256: str
    fetched_at: str
    raw_html: str
    parse_warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class OriginalSource:
    requested_url: str
    final_url: str
    http_status: int | None
    content_sha256: str | None
    fetched_at: str
    title: str = ""
    published_date: str | None = None
    summary: str = ""
    source_level: str = "C"
    raw_html: str | None = None
    error: str | None = None


@dataclass(frozen=True)
class Organization:
    id: int
    name: str
    aliases: tuple[str, ...]


@dataclass(frozen=True)
class MatchResult:
    status: str
    organization: Organization | None
    method: str | None
    raw_names: tuple[str, ...]
    candidate_organizations: tuple[Organization, ...] = ()
    reason: str | None = None


@dataclass(frozen=True)
class NormalizationResult:
    event: dict[str, Any] | None
    rejected_reason: str | None = None
    review_reasons: tuple[str, ...] = ()
    unmatched: bool = False


@dataclass(frozen=True)
class DedupDecision:
    status: str
    reason: str | None = None
    existing_id: str | None = None


@dataclass(frozen=True)
class DateWindow:
    start: date
    end: date
    mode: str


@dataclass
class BatchStats:
    discovered: int = 0
    fetched: int = 0
    raw_records: int = 0
    normalized: int = 0
    accepted: int = 0
    needs_review: int = 0
    unmatched: int = 0
    rejected: int = 0
    duplicates: int = 0
    suspected_duplicates: int = 0
    errors: int = 0

    def as_dict(self) -> dict[str, int]:
        return {
            "discovered": self.discovered,
            "fetched": self.fetched,
            "raw_records": self.raw_records,
            "normalized": self.normalized,
            "accepted": self.accepted,
            "needs_review": self.needs_review,
            "unmatched": self.unmatched,
            "rejected": self.rejected,
            "duplicates": self.duplicates,
            "suspected_duplicates": self.suspected_duplicates,
            "errors": self.errors,
        }
