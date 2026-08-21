from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import tempfile
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence

from pypdf import PdfReader, PdfWriter

try:
    from .parse_reports import (
        PROJECT_ROOT,
        atomic_write_text,
        build_quality_metrics,
        combined_markdown,
        configure_console_encoding,
        non_whitespace_length,
        project_relative,
    )
except ImportError:  # Allow direct execution: python scripts/qianxin/enrich_reports.py
    from parse_reports import (  # type: ignore[no-redef]
        PROJECT_ROOT,
        atomic_write_text,
        build_quality_metrics,
        combined_markdown,
        configure_console_encoding,
        non_whitespace_length,
        project_relative,
    )


DEFAULT_FAST_ROOT = PROJECT_ROOT / "data" / "parsed" / "pymupdf4llm"
DEFAULT_MINERU_ROOT = PROJECT_ROOT / "data" / "parsed" / "mineru"
DEFAULT_MERGED_ROOT = PROJECT_ROOT / "data" / "parsed" / "merged"
DEFAULT_MINERU_EXE = PROJECT_ROOT / ".venv-mineru" / "Scripts" / "mineru.exe"
SCHEMA_VERSION = 1

# MinerU's Chinese model also handles English. These reports contain substantial
# Korean or East-European text and benefit from a more specific OCR model.
LANGUAGE_BY_SHA_PREFIX = {
    "04975abb": "east_slavic",
    "234b2a87": "korean",
    "277a09e9": "korean",
    "f0627876": "korean",
}
DEFAULT_LANGUAGE = "ch"
SKIPPED_BLOCK_TYPES = {"header", "footer", "page_number", "aside"}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: Any) -> None:
    atomic_write_text(path, json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def discover_quality_records(fast_root: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for path in sorted(fast_root.glob("*/*/quality.json")):
        record = read_json(path)
        record["_quality_path"] = str(path.resolve())
        records.append(record)
    return records


def language_for_sha(sha256: str) -> str:
    return LANGUAGE_BY_SHA_PREFIX.get(sha256[:8].lower(), DEFAULT_LANGUAGE)


def pages_requiring_ocr(record: dict[str, Any]) -> list[int]:
    metrics = record["metrics"]
    pages = sorted({int(page) for page in metrics["empty_or_low_text_pages"]})
    page_count = int(record["source"]["pdf_page_count"])
    invalid = [page for page in pages if page < 1 or page > page_count]
    if invalid:
        raise ValueError(f"Invalid OCR page numbers {invalid} for {record['source']['path']}")
    return pages


def create_subset_pdf(source_pdf: Path, pages: Sequence[int], destination: Path) -> None:
    reader = PdfReader(str(source_pdf))
    writer = PdfWriter()
    for page_number in pages:
        writer.add_page(reader.pages[page_number - 1])
    writer.add_metadata(
        {
            "/Title": f"MinerU OCR subset of {source_pdf.name}",
            "/Subject": "Derived file; page mapping is stored in page-map.json",
        }
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(".tmp.pdf")
    with temporary.open("wb") as handle:
        writer.write(handle)
    os.replace(temporary, destination)


def prepare_ocr_inputs(
    records: Sequence[dict[str, Any]],
    mineru_root: Path,
    *,
    overwrite: bool = False,
) -> list[dict[str, Any]]:
    jobs: list[dict[str, Any]] = []
    for record in records:
        pages = pages_requiring_ocr(record)
        if not pages:
            continue
        sha256 = record["source"]["sha256"]
        sha8 = sha256[:8]
        source_pdf = PROJECT_ROOT / Path(record["source"]["path"])
        work_dir = mineru_root / "work" / sha8
        subset_pdf = work_dir / f"{sha8}.pdf"
        page_map_path = work_dir / "page-map.json"
        page_map = {
            "schema_version": SCHEMA_VERSION,
            "source_sha256": sha256,
            "source_pdf": project_relative(source_pdf),
            "subset_pdf": project_relative(subset_pdf),
            "subset_page_count": len(pages),
            "subset_to_source_page": pages,
            "mineru_page_index_base": 0,
            "language": language_for_sha(sha256),
        }
        current_map = read_json(page_map_path) if page_map_path.exists() else None
        if overwrite or not subset_pdf.exists() or current_map != page_map:
            create_subset_pdf(source_pdf, pages, subset_pdf)
            write_json(page_map_path, page_map)
        jobs.append(
            {
                "record": record,
                "sha8": sha8,
                "language": page_map["language"],
                "subset_pdf": subset_pdf,
                "page_map_path": page_map_path,
                "pages": pages,
            }
        )
    return jobs


def expected_content_list(mineru_root: Path, job: dict[str, Any]) -> Path:
    sha8 = job["sha8"]
    return mineru_root / "raw" / job["language"] / sha8 / "ocr" / f"{sha8}_content_list.json"


def mineru_environment(mineru_root: Path) -> dict[str, str]:
    environment = os.environ.copy()
    cache_root = PROJECT_ROOT / "data" / "cache"
    temp_root = cache_root / "tmp"
    temp_root.mkdir(parents=True, exist_ok=True)
    (PROJECT_ROOT / "data" / "models" / "huggingface" / "hub").mkdir(
        parents=True, exist_ok=True
    )
    environment.update(
        {
            "HF_HOME": str(PROJECT_ROOT / "data" / "models" / "huggingface"),
            "HUGGINGFACE_HUB_CACHE": str(
                PROJECT_ROOT / "data" / "models" / "huggingface" / "hub"
            ),
            "MODELSCOPE_CACHE": str(PROJECT_ROOT / "data" / "models" / "modelscope"),
            "MINERU_TOOLS_CONFIG_JSON": str(PROJECT_ROOT / "data" / "state" / "mineru.json"),
            "MINERU_API_OUTPUT_ROOT": str(mineru_root / "api-output"),
            "MINERU_MODEL_SOURCE": "local",
            "MINERU_INTRA_OP_NUM_THREADS": "6",
            "MINERU_INTER_OP_NUM_THREADS": "2",
            "MINERU_PROCESSING_WINDOW_SIZE": "8",
            "MINERU_PDF_RENDER_THREADS": "2",
            "PYTHONIOENCODING": "utf-8",
            "TEMP": str(temp_root),
            "TMP": str(temp_root),
        }
    )
    return environment


def run_mineru_jobs(
    jobs: Sequence[dict[str, Any]],
    mineru_root: Path,
    mineru_exe: Path,
    *,
    overwrite: bool = False,
    dry_run: bool = False,
) -> None:
    if not mineru_exe.is_file():
        raise FileNotFoundError(
            f"MinerU executable not found: {mineru_exe}. Install requirements-mineru.txt first."
        )
    pending = [
        job for job in jobs if overwrite or not expected_content_list(mineru_root, job).is_file()
    ]
    if not pending:
        print("MinerU: all requested OCR outputs already exist; skipping inference.")
        return

    by_language: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for job in pending:
        by_language[job["language"]].append(job)

    staging_parent = PROJECT_ROOT / "data" / "cache" / "mineru-staging"
    staging_parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="batch-", dir=staging_parent) as temporary:
        temporary_root = Path(temporary)
        for language, language_jobs in sorted(by_language.items()):
            input_dir = temporary_root / language
            input_dir.mkdir(parents=True, exist_ok=True)
            for job in language_jobs:
                shutil.copy2(job["subset_pdf"], input_dir / f"{job['sha8']}.pdf")
            output_dir = mineru_root / "raw" / language
            command = [
                str(mineru_exe), "-p", str(input_dir), "-o", str(output_dir),
                "-b", "pipeline", "-m", "ocr", "-l", language,
                "-f", "false", "-t", "true",
            ]
            print(
                f"MinerU: language={language}, reports={len(language_jobs)}, "
                f"pages={sum(len(job['pages']) for job in language_jobs)}"
            )
            if dry_run:
                print("  " + subprocess.list2cmdline(command))
                continue
            output_dir.mkdir(parents=True, exist_ok=True)
            subprocess.run(
                command,
                cwd=PROJECT_ROOT,
                env=mineru_environment(mineru_root),
                check=True,
            )

    if not dry_run:
        missing = [
            str(expected_content_list(mineru_root, job))
            for job in pending
            if not expected_content_list(mineru_root, job).is_file()
        ]
        if missing:
            raise RuntimeError("MinerU completed but output is missing:\n" + "\n".join(missing))


def _text_values(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if isinstance(value, (int, float)):
        return [str(value)]
    if isinstance(value, list):
        result: list[str] = []
        for item in value:
            result.extend(_text_values(item))
        return result
    if isinstance(value, dict):
        for key in ("text", "content", "value"):
            if key in value:
                return _text_values(value[key])
    return []


def mineru_block_to_markdown(block: dict[str, Any]) -> str:
    block_type = str(block.get("type") or "")
    if block_type in SKIPPED_BLOCK_TYPES:
        return ""
    if block_type == "text":
        text = str(block.get("text") or "").strip()
        level = block.get("text_level")
        if text and isinstance(level, int) and level > 0:
            return f"{'#' * min(level, 6)} {text}"
        return text
    if block_type == "list":
        items = _text_values(block.get("list_items"))
        if block.get("sub_type") == "ref":
            return "\n".join(items)
        return "\n".join(f"- {item}" for item in items)
    if block_type in {"equation", "interline_equation"}:
        return str(block.get("text") or block.get("latex") or "").strip()
    if block_type == "table":
        caption = " ".join(_text_values(block.get("table_caption")))
        body = str(block.get("table_body") or "").strip()
        footnote = " ".join(_text_values(block.get("table_footnote")))
        parts = [
            part
            for part in (
                f"**表：{caption}**" if caption else "",
                body,
                f"> 表注：{footnote}" if footnote else "",
            )
            if part
        ]
        return "\n\n".join(parts)
    if block_type in {"image", "chart"}:
        captions = _text_values(block.get("image_caption")) + _text_values(block.get("chart_caption"))
        descriptions = _text_values(block.get("image_body")) + _text_values(block.get("chart_body"))
        label = "；".join(captions + descriptions)
        return f"[图像：{label}]" if label else "[图像]"
    if block_type == "code":
        code = str(block.get("code_body") or block.get("text") or "").strip()
        caption = " ".join(_text_values(block.get("code_caption")))
        parts = [f"**代码：{caption}**"] if caption else []
        if code:
            parts.append(f"```\n{code}\n```")
        return "\n\n".join(parts)
    if block_type == "page_footnote":
        text = str(block.get("text") or "").strip()
        return f"> 页下注：{text}" if text else ""
    return str(block.get("text") or "").strip()


def load_ocr_pages(job: dict[str, Any], mineru_root: Path) -> dict[int, dict[str, Any]]:
    content_path = expected_content_list(mineru_root, job)
    blocks = read_json(content_path)
    page_map = read_json(job["page_map_path"])["subset_to_source_page"]
    grouped: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for block in blocks:
        subset_index = int(block["page_idx"])
        if subset_index < 0 or subset_index >= len(page_map):
            raise ValueError(f"MinerU page index {subset_index} is outside page map: {content_path}")
        grouped[int(page_map[subset_index])].append(block)

    result: dict[int, dict[str, Any]] = {}
    for original_page in page_map:
        page_blocks = grouped.get(int(original_page), [])
        markdown = "\n\n".join(
            rendered
            for block in page_blocks
            if (rendered := mineru_block_to_markdown(block).strip())
        ).strip()
        result[int(original_page)] = {
            "markdown": markdown,
            "non_whitespace_char_count": non_whitespace_length(markdown),
            "blocks": page_blocks,
            "content_list": project_relative(content_path),
            "language": job["language"],
        }
    return result


def merge_record(
    record: dict[str, Any],
    merged_root: Path,
    ocr_pages: dict[int, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    ocr_pages = ocr_pages or {}
    source = record["source"]
    organization = source["organization_directory"]
    sha8 = source["sha256"][:8]
    fast_document_path = PROJECT_ROOT / Path(record["outputs"]["json"])
    fast_document = read_json(fast_document_path)
    merged_pages: list[dict[str, Any]] = []
    recovered_pages: list[int] = []
    unresolved_pages: list[int] = []

    for fast_page in fast_document["pages"]:
        page_number = int(fast_page["page_number"])
        fast_markdown = str(fast_page.get("markdown") or "").strip()
        fast_chars = non_whitespace_length(fast_markdown)
        ocr = ocr_pages.get(page_number)
        ocr_markdown = str(ocr.get("markdown") or "").strip() if ocr else ""
        ocr_chars = non_whitespace_length(ocr_markdown)
        use_ocr = bool(ocr and ocr_chars > fast_chars)
        selected = ocr_markdown if use_ocr else fast_markdown
        if use_ocr:
            recovered_pages.append(page_number)
        if non_whitespace_length(selected) < 50:
            unresolved_pages.append(page_number)
        merged_pages.append(
            {
                "page_number": page_number,
                "markdown": selected,
                "source_parser": "mineru_ocr" if use_ocr else "pymupdf4llm",
                "non_whitespace_char_count": non_whitespace_length(selected),
                "fast_char_count": fast_chars,
                "ocr_attempted": ocr is not None,
                "ocr_char_count": ocr_chars if ocr else None,
                "ocr_language": ocr.get("language") if ocr else None,
                "ocr_content_list": ocr.get("content_list") if ocr else None,
                "ocr_blocks": ocr.get("blocks") if ocr else None,
            }
        )

    page_texts = [page["markdown"] for page in merged_pages]
    metrics = build_quality_metrics(
        page_texts,
        table_count=sum(text.count("<table") for text in page_texts),
        image_count=int(record["metrics"].get("pdf_image_count", 0)),
    )
    if metrics["status"] == "needs_ocr":
        summary_status = "needs_manual_review"
    elif unresolved_pages:
        summary_status = "ready_for_summary_with_visual_gaps"
    else:
        summary_status = "ready_for_summary"
    metrics.update(
        {
            "status": summary_status,
            "fast_parser_status": record["metrics"]["status"],
            "ocr_attempted_pages": sorted(ocr_pages),
            "ocr_recovered_pages": recovered_pages,
            "unresolved_low_text_pages": unresolved_pages,
        }
    )

    destination = merged_root / organization / sha8
    markdown_path = destination / "report.md"
    document_path = destination / "document.json"
    quality_path = destination / "quality.json"
    generated_at = utc_now()
    document = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": generated_at,
        "generator": {
            "name": "pymupdf4llm-mineru-page-merge",
            "fast_parser": "pymupdf4llm",
            "fallback_parser": "MinerU pipeline OCR",
        },
        "source": source,
        "pages": merged_pages,
    }
    quality = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": generated_at,
        "source": source,
        "metrics": metrics,
        "outputs": {
            "markdown": project_relative(markdown_path),
            "json": project_relative(document_path),
            "quality": project_relative(quality_path),
        },
    }
    atomic_write_text(markdown_path, combined_markdown(source["path"], merged_pages))
    write_json(document_path, document)
    write_json(quality_path, quality)
    return quality


def merge_all(
    records: Sequence[dict[str, Any]],
    jobs: Sequence[dict[str, Any]],
    mineru_root: Path,
    merged_root: Path,
    *,
    dry_run: bool = False,
) -> dict[str, Any]:
    jobs_by_sha = {job["record"]["source"]["sha256"]: job for job in jobs}
    qualities: list[dict[str, Any]] = []
    for record in records:
        job = jobs_by_sha.get(record["source"]["sha256"])
        ocr_pages: dict[int, dict[str, Any]] = {}
        if job and not dry_run:
            ocr_pages = load_ocr_pages(job, mineru_root)
        if not dry_run:
            qualities.append(merge_record(record, merged_root, ocr_pages))

    status_counts = Counter(item["metrics"]["status"] for item in qualities)
    summary = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": utc_now(),
        "report_count": len(qualities),
        "status_counts": dict(sorted(status_counts.items())),
        "ocr_report_count": len(jobs),
        "ocr_page_count": sum(len(job["pages"]) for job in jobs),
        "ocr_recovered_page_count": sum(
            len(item["metrics"]["ocr_recovered_pages"]) for item in qualities
        ),
        "reports": qualities,
    }
    if not dry_run:
        write_json(merged_root / "batch-summary.json", summary)
    return summary


def filter_records(records: Iterable[dict[str, Any]], sha_prefixes: Sequence[str]) -> list[dict[str, Any]]:
    prefixes = [prefix.lower() for prefix in sha_prefixes]
    if not prefixes:
        return list(records)
    records = list(records)
    selected = [
        record
        for record in records
        if any(record["source"]["sha256"].lower().startswith(prefix) for prefix in prefixes)
    ]
    missing = [
        prefix
        for prefix in prefixes
        if not any(record["source"]["sha256"].lower().startswith(prefix) for record in records)
    ]
    if missing:
        raise ValueError(f"No parsed report matches SHA prefix(es): {', '.join(missing)}")
    return selected


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run MinerU OCR only on weak pages, then merge all reports page by page."
    )
    parser.add_argument("--fast-root", type=Path, default=DEFAULT_FAST_ROOT)
    parser.add_argument("--mineru-root", type=Path, default=DEFAULT_MINERU_ROOT)
    parser.add_argument("--merged-root", type=Path, default=DEFAULT_MERGED_ROOT)
    parser.add_argument("--mineru-exe", type=Path, default=DEFAULT_MINERU_EXE)
    parser.add_argument("--sha", action="append", default=[], help="Process matching SHA prefix; repeatable")
    parser.add_argument("--overwrite-ocr", action="store_true")
    parser.add_argument("--prepare-only", action="store_true")
    parser.add_argument("--merge-only", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    configure_console_encoding()
    args = build_argument_parser().parse_args(argv)
    if args.prepare_only and args.merge_only:
        raise ValueError("--prepare-only and --merge-only cannot be used together")
    started = time.perf_counter()
    all_records = discover_quality_records(args.fast_root.resolve())
    if not all_records:
        raise FileNotFoundError(f"No quality.json files found below {args.fast_root}")
    selected_records = filter_records(all_records, args.sha)
    ocr_records = [record for record in selected_records if pages_requiring_ocr(record)]
    jobs = prepare_ocr_inputs(ocr_records, args.mineru_root.resolve(), overwrite=args.overwrite_ocr)
    print(
        f"Selected {len(selected_records)} reports; {len(jobs)} need OCR "
        f"({sum(len(job['pages']) for job in jobs)} pages)."
    )
    if args.prepare_only:
        return 0
    if not args.merge_only:
        run_mineru_jobs(
            jobs,
            args.mineru_root.resolve(),
            args.mineru_exe.resolve(),
            overwrite=args.overwrite_ocr,
            dry_run=args.dry_run,
        )
    records_to_merge = selected_records if args.sha else all_records
    summary = merge_all(
        records_to_merge,
        jobs,
        args.mineru_root.resolve(),
        args.merged_root.resolve(),
        dry_run=args.dry_run,
    )
    print(
        f"Merge complete: {summary['report_count']} reports, statuses={summary['status_counts']}, "
        f"elapsed={time.perf_counter() - started:.1f}s"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
