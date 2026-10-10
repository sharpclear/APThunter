"""Use DeepSeek to review DGA-like domain candidates from a CSV file.

Fill INPUT_CSV_FILE at the top of this file before running. If INPUT_CSV_FILE
is only a file name, it is resolved from models/detection/outputs.

The script only asks the LLM to judge DGA-like string characteristics. It must
not be treated as DNS, WHOIS, certificate, traffic, or threat-intelligence
evidence.
"""

from __future__ import annotations

import csv
import json
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import requests

try:
    from .dga_detection_utils import extract_sld, normalize_domain
except ImportError:
    from dga_detection_utils import extract_sld, normalize_domain


# Fill these manually before running, or set DEEPSEEK_API_KEY in the environment.
INPUT_CSV_FILE = "dga_char_cnn_predictions_score_0p999_to_1p0.csv"
DEEPSEEK_API_KEY = ""

# Optional. Leave empty to auto-detect. Priority:
# domain, url, hostname, registered_domain, fqdn, original_domain, normalized_domain
DOMAIN_COLUMN = ""

# Optional. Leave empty to generate from INPUT_CSV_FILE.
OUTPUT_FILE_NAME = ""


SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_INPUT_DIR = SCRIPT_DIR / "outputs"
LLM_OUTPUT_DIR = SCRIPT_DIR / "llm_outputs"

DEEPSEEK_API_KEY_ENV = "DEEPSEEK_API_KEY"
DEEPSEEK_API_URL = "https://api.deepseek.com/chat/completions"
MODEL_NAME = "deepseek-v4-flash"

BATCH_SIZE = 1000
MAX_WORKERS = 10
TEMPERATURE = 0.0
MAX_TOKENS = 384000
REQUEST_TIMEOUT_SECONDS = 900
MAX_RETRIES = 3
RETRY_SLEEP_SECONDS = 5

DOMAIN_COLUMN_PRIORITY = [
    "domain",
    "url",
    "hostname",
    "registered_domain",
    "fqdn",
    "original_domain",
    "normalized_domain",
]

OUTPUT_FIELDS = [
    "domain",
    "normalized_domain",
    "sld",
    "dga_likelihood",
    "label",
    "reason",
    "key_features",
]


SYSTEM_PROMPT = """你是一个网络安全分析助手，任务是仅根据域名字符串本身进行 DGA-like 可疑性分析。

重要限制：
- 只能基于域名字符串本身判断。
- 不要假设你拥有 DNS、WHOIS、证书、网页内容、流量日志或威胁情报。
- 结论不能写成“确认是 DGA 域名”，只能写成“具有 DGA-like 生成倾向”或“不具有明显 DGA-like 特征”。
- 不要把钓鱼、仿冒、C2、Fast Flux、DNS 隧道、水坑攻击、失陷合法域名和 DGA 混为一谈。

判断重点：
1. 字符随机性：无意义字母组合、低可读性、不常见 n-gram、高熵。
2. 长度结构：SLD 异常长、连续辅音、连续数字、字母数字无规律混杂。
3. 可读性：正常单词、品牌词、拼音、缩写、业务词不要轻易判为 DGA。
4. DGA-like 倾向：随机型、伪随机型、词典异常拼接、短随机型。
5. 避免误判：年份、地区缩写、cloud、ai、data、tech、shop、service、app、online、store 等常见业务词，若整体可读，不要轻易判为 DGA。

输出要求：
- 只输出合法 JSON。
- JSON 顶层格式必须是 {"results": [...]}。
- results 中每个对象必须包含：
  domain, normalized_domain, sld, dga_likelihood, label, reason, key_features
- dga_likelihood 是 0 到 1 的小数。
- label 只能是 likely_dga、suspicious_dga_like、unlikely_dga、uncertain。
- reason 不超过 40 个中文字符。
- key_features 是字符串数组，元素可包括 high_entropy、low_readability、random_ngram、digit_mix、dictionary_words、normal_business_term、short_readable、consonant_run、digit_run、phishing_like_not_dga 等。

打分标准：
- 0.80 - 1.00：likely_dga，强烈 DGA-like
- 0.55 - 0.79：suspicious_dga_like，有一定 DGA-like 倾向
- 0.30 - 0.54：uncertain，仅凭字符串难以判断
- 0.00 - 0.29：unlikely_dga，无明显 DGA-like 特征
"""


def main() -> None:
    input_path = resolve_input_path(INPUT_CSV_FILE)
    api_key = (DEEPSEEK_API_KEY.strip() or os.environ.get(DEEPSEEK_API_KEY_ENV, "").strip())
    if not api_key:
        raise ValueError(
            "DEEPSEEK_API_KEY must not be empty. Fill it at the top of this file "
            f"or set environment variable {DEEPSEEK_API_KEY_ENV}."
        )

    rows, columns = read_csv_rows(input_path)
    if not rows:
        raise ValueError(f"Input CSV contains no records: {input_path}")

    domain_column = resolve_domain_column(columns)
    output_path = resolve_output_path(input_path)
    LLM_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    all_results: list[dict[str, Any]] = []
    batches = list(chunked(rows, BATCH_SIZE))
    print(f"Input CSV: {input_path}")
    print(f"Domain column: {domain_column}")
    print(f"Rows: {len(rows)}")
    print(f"Batches: {len(batches)} x up to {BATCH_SIZE}")
    print(f"Concurrent workers: {MAX_WORKERS}")

    batch_jobs = []
    for batch_index, batch_rows in enumerate(batches, start=1):
        domains = [str(row.get(domain_column, "")).strip() for row in batch_rows]
        domain_items = build_domain_items(domains)
        batch_jobs.append((batch_index, domain_items))

    completed_batches: dict[int, list[dict[str, Any]]] = {}
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_batch = {
            executor.submit(process_batch, api_key, domain_items, batch_index, len(batches)): batch_index
            for batch_index, domain_items in batch_jobs
        }
        for future in as_completed(future_to_batch):
            batch_index = future_to_batch[future]
            completed_index, batch_rows = future.result()
            completed_batches[completed_index] = batch_rows

            all_results = []
            for ordered_index in sorted(completed_batches):
                all_results.extend(completed_batches[ordered_index])
            write_csv_rows(output_path, all_results)
            print(f"Saved progress after batch {batch_index}: {len(all_results)} rows")

    print(f"Saved LLM judgement CSV: {output_path}")


def resolve_input_path(input_csv_file: str) -> Path:
    value = input_csv_file.strip()
    if not value:
        raise ValueError("INPUT_CSV_FILE must not be empty.")

    candidate = Path(value)
    if candidate.is_absolute() and candidate.is_file():
        return candidate
    if candidate.is_file():
        return candidate.resolve()

    from_outputs = DEFAULT_INPUT_DIR / value
    if from_outputs.is_file():
        return from_outputs.resolve()

    raise FileNotFoundError(
        f"Input CSV not found. Tried: {candidate.resolve()} and {from_outputs.resolve()}"
    )


def resolve_domain_column(columns: list[str]) -> str:
    if DOMAIN_COLUMN.strip():
        column = DOMAIN_COLUMN.strip()
        if column not in columns:
            raise ValueError(f"DOMAIN_COLUMN not found: {column!r}. Available columns: {columns}")
        return column

    for column in DOMAIN_COLUMN_PRIORITY:
        if column in columns:
            return column

    raise ValueError(
        "Unable to determine domain column. Available columns: "
        f"{columns}. Please set DOMAIN_COLUMN at the top of the script."
    )


def resolve_output_path(input_path: Path) -> Path:
    if OUTPUT_FILE_NAME.strip():
        return LLM_OUTPUT_DIR / OUTPUT_FILE_NAME.strip()
    return LLM_OUTPUT_DIR / f"{input_path.stem}_deepseek_llm_judgement.csv"


def read_csv_rows(path: Path) -> tuple[list[dict[str, str]], list[str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        columns = list(reader.fieldnames or [])
        rows = [dict(row) for row in reader]
    if not columns:
        raise ValueError(f"Input CSV has no header: {path}")
    return rows, columns


def write_csv_rows(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=OUTPUT_FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def build_domain_items(domains: list[str]) -> list[dict[str, str]]:
    items = []
    for domain in domains:
        normalized = normalize_domain(domain)
        sld = extract_sld(normalized)
        items.append(
            {
                "domain": domain,
                "normalized_domain": normalized,
                "sld": sld,
            }
        )
    return items


def judge_batch(
    api_key: str,
    domain_items: list[dict[str, str]],
    batch_index: int,
) -> list[dict[str, Any]]:
    payload = {
        "model": MODEL_NAME,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": build_user_prompt(domain_items, batch_index),
            },
        ],
        "temperature": TEMPERATURE,
        "max_tokens": MAX_TOKENS,
        "stream": False,
        "response_format": {"type": "json_object"},
    }
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    last_error: Exception | None = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            response = requests.post(
                DEEPSEEK_API_URL,
                headers=headers,
                json=payload,
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
            response.raise_for_status()
            data = response.json()
            content = data["choices"][0]["message"]["content"]
            parsed = json.loads(content)
            results = parsed.get("results", [])
            if not isinstance(results, list):
                raise ValueError("DeepSeek JSON response field 'results' must be a list.")
            return results
        except Exception as exc:
            last_error = exc
            if attempt < MAX_RETRIES:
                print(f"Batch {batch_index} attempt {attempt} failed: {exc}. Retrying...")
                time.sleep(RETRY_SLEEP_SECONDS)

    raise RuntimeError(f"Batch {batch_index} failed after {MAX_RETRIES} attempts: {last_error}")


def process_batch(
    api_key: str,
    domain_items: list[dict[str, str]],
    batch_index: int,
    total_batches: int,
) -> tuple[int, list[dict[str, Any]]]:
    print(f"Calling DeepSeek batch {batch_index}/{total_batches} ({len(domain_items)} domains)...")
    batch_results = judge_batch(api_key, domain_items, batch_index)
    normalized_rows = normalize_llm_results(batch_results, domain_items)
    print(f"Finished DeepSeek batch {batch_index}/{total_batches}")
    return batch_index, normalized_rows


def build_user_prompt(domain_items: list[dict[str, str]], batch_index: int) -> str:
    return (
        "请分析以下域名。再次强调：只基于字符串本身判断，不要编造 DNS、WHOIS、IP、证书、网页、流量或威胁情报。\n"
        "请输出 JSON，格式为 {\"results\": [...]}，每个域名必须对应一个结果对象。\n"
        f"batch_index: {batch_index}\n"
        "domains_json:\n"
        f"{json.dumps(domain_items, ensure_ascii=False)}"
    )


def normalize_llm_results(
    results: list[dict[str, Any]],
    domain_items: list[dict[str, str]],
) -> list[dict[str, Any]]:
    by_domain = {str(result.get("domain", "")): result for result in results}
    normalized_rows = []

    for item in domain_items:
        result = by_domain.get(item["domain"], {})
        score = safe_float(result.get("dga_likelihood", 0.0))
        label = str(result.get("label", "uncertain"))
        if label not in {"likely_dga", "suspicious_dga_like", "unlikely_dga", "uncertain"}:
            label = label_from_score(score)

        key_features = result.get("key_features", [])
        if isinstance(key_features, list):
            key_features_text = ",".join(str(feature) for feature in key_features)
        else:
            key_features_text = str(key_features)

        normalized_rows.append(
            {
                "domain": item["domain"],
                "normalized_domain": str(result.get("normalized_domain") or item["normalized_domain"]),
                "sld": str(result.get("sld") or item["sld"]),
                "dga_likelihood": f"{score:.4f}",
                "label": label,
                "reason": str(result.get("reason", ""))[:80],
                "key_features": key_features_text,
            }
        )
    return normalized_rows


def safe_float(value: Any) -> float:
    try:
        number = float(value)
    except Exception:
        number = 0.0
    return max(0.0, min(1.0, number))


def label_from_score(score: float) -> str:
    if score >= 0.80:
        return "likely_dga"
    if score >= 0.55:
        return "suspicious_dga_like"
    if score >= 0.30:
        return "uncertain"
    return "unlikely_dga"


def chunked(rows: list[dict[str, str]], size: int) -> list[list[dict[str, str]]]:
    return [rows[index : index + size] for index in range(0, len(rows), size)]


if __name__ == "__main__":
    main()
