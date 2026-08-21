from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import sys
import tempfile
import time
import unicodedata
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence

import pymupdf
import pymupdf4llm


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_INPUT_DIR = PROJECT_ROOT / "data" / "reports"
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "data" / "parsed" / "pymupdf4llm"
SCHEMA_VERSION = 1


def configure_console_encoding() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(encoding="utf-8", errors="backslashreplace")


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def project_relative(path: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(PROJECT_ROOT).as_posix()
    except ValueError:
        return str(resolved)


def json_safe(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, dict):
        return {str(key): json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [json_safe(item) for item in value]
    if hasattr(value, "__iter__") and not isinstance(value, (bytes, bytearray)):
        try:
            return [json_safe(item) for item in value]
        except TypeError:
            pass
    return str(value)


def atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
    except Exception:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def non_whitespace_length(text: str) -> int:
    return sum(not character.isspace() for character in text)


def suspicious_character_count(text: str) -> int:
    count = text.count("\ufffd")
    count += len(re.findall(r"\(cid:\d+\)", text, flags=re.IGNORECASE))
    for character in text:
        codepoint = ord(character)
        category = unicodedata.category(character)
        if 0xE000 <= codepoint <= 0xF8FF:
            count += 1
        elif category == "Cc" and character not in "\n\r\t":
            count += 1
    return count


def normalize_repeated_line(line: str) -> str:
    value = re.sub(r"\s+", " ", line).strip()
    value = re.sub(r"\b\d{1,4}\b", "#", value)
    return value


def repeated_lines(page_texts: Sequence[str]) -> list[dict[str, Any]]:
    page_frequency: Counter[str] = Counter()
    original_examples: dict[str, str] = {}
    for text in page_texts:
        unique_on_page: set[str] = set()
        for line in text.splitlines():
            stripped = line.strip().strip("#*_`| ")
            if not 3 <= len(stripped) <= 180:
                continue
            normalized = normalize_repeated_line(stripped)
            if len(normalized) < 3:
                continue
            unique_on_page.add(normalized)
            original_examples.setdefault(normalized, stripped)
        page_frequency.update(unique_on_page)

    threshold = max(3, math.ceil(len(page_texts) * 0.6))
    return [
        {"text": original_examples[line], "page_count": count}
        for line, count in page_frequency.most_common()
        if count >= threshold
    ][:20]


def build_quality_metrics(
    page_texts: Sequence[str],
    *,
    table_count: int,
    image_count: int,
    min_page_chars: int = 50,
) -> dict[str, Any]:
    page_char_counts = [non_whitespace_length(text) for text in page_texts]
    page_count = len(page_texts)
    text_char_count = sum(page_char_counts)
    textual_pages = sum(count >= min_page_chars for count in page_char_counts)
    empty_pages = [
        index + 1 for index, count in enumerate(page_char_counts) if count < min_page_chars
    ]
    combined = "\n".join(page_texts)
    suspicious_count = suspicious_character_count(combined)
    suspicious_ratio = suspicious_count / max(text_char_count, 1)
    coverage_ratio = textual_pages / max(page_count, 1)
    average_chars = text_char_count / max(page_count, 1)
    heading_count = len(re.findall(r"(?m)^#{1,6}\s+\S", combined))
    table_markers = len(re.findall(r"(?m)^\s*\|.+\|\s*$", combined))
    repeated = repeated_lines(page_texts)

    warnings: list[str] = []
    if coverage_ratio < 0.5 or average_chars < 80:
        status = "needs_ocr"
        warnings.append("文本覆盖率过低，疑似扫描件或图片型 PDF，应转入 OCR/MinerU。")
    elif coverage_ratio < 0.9:
        status = "needs_review"
        warnings.append("部分页面文本不足，建议检查图片页、目录页或解析遗漏。")
    elif suspicious_ratio > 0.005:
        status = "needs_review"
        warnings.append("检测到较高比例的替换字符、CID 或私用区字符，可能存在乱码。")
    else:
        status = "ready_for_small_model"

    if heading_count == 0:
        warnings.append("未识别 Markdown 标题层级，后续应按页码而非标题切分。")
    if repeated:
        warnings.append("检测到跨页重复行，可能包含尚未移除的页眉或页脚。")

    return {
        "status": status,
        "page_count": page_count,
        "textual_page_count": textual_pages,
        "textual_page_ratio": round(coverage_ratio, 4),
        "empty_or_low_text_pages": empty_pages,
        "non_whitespace_char_count": text_char_count,
        "average_chars_per_page": round(average_chars, 2),
        "min_chars_on_page": min(page_char_counts, default=0),
        "max_chars_on_page": max(page_char_counts, default=0),
        "suspicious_character_count": suspicious_count,
        "suspicious_character_ratio": round(suspicious_ratio, 8),
        "markdown_heading_count": heading_count,
        "detected_table_count": table_count,
        "markdown_table_line_count": table_markers,
        "pdf_image_count": image_count,
        "repeated_lines": repeated,
        "warnings": warnings,
    }


def combined_markdown(source_path: str, pages: Sequence[dict[str, Any]]) -> str:
    sections = [f"<!-- source: {source_path} -->"]
    for page in pages:
        sections.append(f"<!-- page: {page['page_number']} -->")
        sections.append(str(page["markdown"]).strip())
    return "\n\n".join(sections).rstrip() + "\n"


def output_directory(output_root: Path, pdf_path: Path, source_sha256: str) -> Path:
    organization = pdf_path.parent.name
    return output_root / organization / source_sha256[:8]


def parse_pdf(
    pdf_path: Path,
    output_root: Path,
    *,
    overwrite: bool = False,
    min_page_chars: int = 50,
    show_progress: bool = False,
) -> dict[str, Any]:
    pdf_path = pdf_path.resolve()
    if not pdf_path.is_file() or pdf_path.suffix.lower() != ".pdf":
        raise ValueError(f"Not a PDF file: {pdf_path}")

    source_sha256 = sha256_file(pdf_path)
    destination = output_directory(output_root.resolve(), pdf_path, source_sha256)
    quality_path = destination / "quality.json"
    if quality_path.exists() and not overwrite:
        existing = json.loads(quality_path.read_text(encoding="utf-8"))
        if existing.get("source", {}).get("sha256") == source_sha256:
            return {**existing, "skipped_existing": True}
        raise FileExistsError(f"Output exists for different content: {destination}")

    started = time.perf_counter()
    source_path = project_relative(pdf_path)
    with pymupdf.open(pdf_path) as document:
        pdf_metadata = json_safe(document.metadata)
        pdf_page_count = document.page_count
        page_image_counts = [len(page.get_images(full=True)) for page in document]

        raw_chunks = pymupdf4llm.to_markdown(
            document,
            page_chunks=True,
            page_separators=False,
            write_images=False,
            embed_images=False,
            extract_words=False,
            show_progress=show_progress,
        )

    if not isinstance(raw_chunks, list):
        raise TypeError("PyMuPDF4LLM did not return page chunks")

    pages: list[dict[str, Any]] = []
    table_count = 0
    for index, chunk in enumerate(raw_chunks):
        markdown = str(chunk.get("text") or "")
        tables = json_safe(chunk.get("tables") or [])
        images = json_safe(chunk.get("images") or [])
        graphics = json_safe(chunk.get("graphics") or [])
        table_count += len(tables)
        pages.append(
            {
                "page_number": index + 1,
                "markdown": markdown,
                "non_whitespace_char_count": non_whitespace_length(markdown),
                "toc_items": json_safe(chunk.get("toc_items") or []),
                "tables": tables,
                "images": images,
                "graphics": graphics,
                "pdf_image_count": page_image_counts[index]
                if index < len(page_image_counts)
                else 0,
            }
        )

    page_texts = [page["markdown"] for page in pages]
    metrics = build_quality_metrics(
        page_texts,
        table_count=table_count,
        image_count=sum(page_image_counts),
        min_page_chars=min_page_chars,
    )
    metrics["parser_page_count_matches_pdf"] = len(pages) == pdf_page_count
    if len(pages) != pdf_page_count:
        metrics["status"] = "needs_review"
        metrics["warnings"].append("解析页数与 PDF 页数不一致。")

    elapsed = time.perf_counter() - started
    generated_at = datetime.now(timezone.utc).isoformat()
    generator = {
        "name": "pymupdf4llm",
        "version": getattr(pymupdf4llm, "__version__", "unknown"),
        "pymupdf_version": getattr(pymupdf, "__version__", "unknown"),
        "layout_extension_enabled": False,
        "ocr_enabled": False,
    }
    source = {
        "path": source_path,
        "file_name": pdf_path.name,
        "organization_directory": pdf_path.parent.name,
        "sha256": source_sha256,
        "file_size": pdf_path.stat().st_size,
        "pdf_page_count": pdf_page_count,
        "pdf_metadata": pdf_metadata,
    }
    document_json = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": generated_at,
        "generator": generator,
        "source": source,
        "pages": pages,
    }
    quality = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": generated_at,
        "generator": generator,
        "source": source,
        "elapsed_seconds": round(elapsed, 3),
        "metrics": metrics,
        "outputs": {
            "markdown": project_relative(destination / "report.md"),
            "json": project_relative(destination / "document.json"),
            "quality": project_relative(quality_path),
        },
    }

    atomic_write_text(destination / "report.md", combined_markdown(source_path, pages))
    atomic_write_text(
        destination / "document.json",
        json.dumps(document_json, ensure_ascii=False, indent=2) + "\n",
    )
    atomic_write_text(
        quality_path, json.dumps(quality, ensure_ascii=False, indent=2) + "\n"
    )
    return quality


def collect_pdf_paths(input_dir: Path, explicit_paths: Iterable[Path]) -> list[Path]:
    paths = list(explicit_paths)
    if not paths:
        paths = list(input_dir.rglob("*.pdf"))
    unique: dict[str, Path] = {}
    for path in paths:
        resolved = path.resolve()
        unique[str(resolved).casefold()] = resolved
    return sorted(unique.values(), key=lambda item: str(item).casefold())


def write_batch_summary(output_root: Path, results: Sequence[dict[str, Any]]) -> Path:
    generated = [result for result in results if "source" in result]
    counts = Counter(result["metrics"]["status"] for result in generated)
    payload = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "parser": "pymupdf4llm",
        "report_count": len(generated),
        "status_counts": dict(sorted(counts.items())),
        "reports": generated,
    }
    path = output_root / "batch-summary.json"
    atomic_write_text(path, json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
    return path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Parse downloaded Qianxin PDF reports into page-aware Markdown and JSON."
    )
    parser.add_argument("--input-dir", type=Path, default=DEFAULT_INPUT_DIR)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument(
        "--pdf",
        type=Path,
        action="append",
        default=[],
        help="Parse one PDF; repeat this option for multiple PDFs.",
    )
    parser.add_argument("--limit", type=int, help="Only parse the first N selected PDFs.")
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument("--show-progress", action="store_true")
    parser.add_argument("--min-page-chars", type=int, default=50)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    configure_console_encoding()
    args = build_parser().parse_args(argv)
    if args.limit is not None and args.limit < 1:
        raise SystemExit("--limit must be at least 1")
    if args.min_page_chars < 1:
        raise SystemExit("--min-page-chars must be at least 1")

    paths = collect_pdf_paths(args.input_dir, args.pdf)
    if args.limit is not None:
        paths = paths[: args.limit]
    if not paths:
        raise SystemExit("No PDF files selected")

    results: list[dict[str, Any]] = []
    failures = 0
    for index, path in enumerate(paths, 1):
        print(f"[{index}/{len(paths)}] {project_relative(path)}", flush=True)
        try:
            result = parse_pdf(
                path,
                args.output_dir,
                overwrite=args.overwrite,
                min_page_chars=args.min_page_chars,
                show_progress=args.show_progress,
            )
            results.append(result)
            status = result["metrics"]["status"]
            suffix = " (existing)" if result.get("skipped_existing") else ""
            print(
                f"  {status}: {result['metrics']['non_whitespace_char_count']} chars, "
                f"{result['elapsed_seconds']}s{suffix}",
                flush=True,
            )
        except Exception as exc:
            failures += 1
            print(f"  ERROR: {exc}", file=sys.stderr, flush=True)

    summary_path = write_batch_summary(args.output_dir.resolve(), results)
    print(f"Batch summary: {project_relative(summary_path)}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
