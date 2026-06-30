from __future__ import annotations

import argparse
import re
from pathlib import Path
from typing import Any, Sequence
from urllib.parse import urlsplit

import pandas as pd
import tldextract


READ_ENCODINGS = ("utf-8-sig", "utf-8", "gbk")
NORMALIZED_FIELDS = [
    "raw",
    "host",
    "normalized_domain",
    "registered_domain",
    "sld",
    "suffix",
    "subdomain",
    "sld_clean",
    "sld_no_hyphen",
    "sld_confusable_norm",
    "is_punycode",
    "starts_with_xn",
    "label_count",
]

CONFUSABLE_TRANSLATION = str.maketrans(
    {
        "0": "o",
        "1": "l",
        "3": "e",
        "5": "s",
        "@": "a",
        "q": "g",
    }
)

# Use the packaged Public Suffix List snapshot so normalization does not depend
# on live network access.
TLD_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=())


def confusable_normalize(text: str) -> str:
    """Normalize common digit/symbol substitutions used in lookalike domains."""
    if text is None:
        return ""
    normalized = str(text).lower().translate(CONFUSABLE_TRANSLATION)
    normalized = normalized.replace("rn", "m")
    normalized = normalized.replace("vv", "w")
    return normalized


def normalize_domain(raw: str) -> dict[str, Any]:
    """Normalize a URL or domain string and extract reusable domain components."""
    raw_value = "" if pd.isna(raw) else str(raw).strip()
    host = _extract_host(raw_value)
    labels = [label for label in host.split(".") if label]
    extracted = TLD_EXTRACTOR(host) if host else TLD_EXTRACTOR("")

    sld = extracted.domain or ""
    suffix = extracted.suffix or ""
    registered_domain = _join_domain(sld, suffix) if sld else ""
    sld_clean = re.sub(r"[^a-z0-9-]+", "", sld.lower())

    return {
        "raw": raw_value,
        "host": host,
        "normalized_domain": host,
        "registered_domain": registered_domain,
        "sld": sld,
        "suffix": suffix,
        "subdomain": extracted.subdomain or "",
        "sld_clean": sld_clean,
        "sld_no_hyphen": sld_clean.replace("-", ""),
        "sld_confusable_norm": confusable_normalize(sld_clean),
        "is_punycode": any(label.startswith("xn--") for label in labels),
        "starts_with_xn": host.startswith("xn--"),
        "label_count": len(labels),
    }


def normalize_dataframe(df: pd.DataFrame, domain_col: str) -> pd.DataFrame:
    """Append normalized domain fields for each row in a dataframe."""
    if domain_col not in df.columns:
        raise ValueError(f"domain column not found: {domain_col}")

    normalized = pd.DataFrame(
        [normalize_domain(value) for value in df[domain_col]],
        columns=NORMALIZED_FIELDS,
    )
    result = df.copy()
    for column in NORMALIZED_FIELDS:
        result[column] = normalized[column].values
    return result


def read_table(path: str | Path) -> pd.DataFrame:
    input_path = Path(path)
    if input_path.suffix.lower() in {".xlsx", ".xls"}:
        return pd.read_excel(input_path)

    errors: list[str] = []
    for encoding in READ_ENCODINGS:
        try:
            return pd.read_csv(input_path, encoding=encoding)
        except UnicodeDecodeError as exc:
            errors.append(f"{encoding}: {exc}")
    raise ValueError(f"failed to read {input_path}: {'; '.join(errors)}")


def _extract_host(raw_value: str) -> str:
    if not raw_value:
        return ""

    value = raw_value.strip().strip("'\"").replace("\\", "/")
    parsed = urlsplit(value if _has_scheme(value) else f"//{value}")
    host = parsed.hostname or ""
    host = host.lower().strip().strip(".")

    if host.startswith("www."):
        host = host[4:]

    return ".".join(label for label in host.split(".") if label)


def _has_scheme(value: str) -> bool:
    return re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value) is not None


def _join_domain(sld: str, suffix: str) -> str:
    return f"{sld}.{suffix}" if suffix else sld


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Normalize domain strings and extract registered-domain components."
    )
    parser.add_argument("--input", required=True, help="Input CSV file path.")
    parser.add_argument("--domain-col", required=True, help="Column containing domains or URLs.")
    parser.add_argument("--output", required=True, help="Output CSV file path.")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> None:
    args = parse_args(argv)
    input_path = Path(args.input)
    output_path = Path(args.output)

    df = read_table(input_path)
    normalized = normalize_dataframe(df, args.domain_col)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    normalized.to_csv(output_path, index=False, encoding="utf-8-sig")

    valid_hosts = int(normalized["host"].astype(bool).sum())
    print(f"input_rows={len(df)}")
    print(f"output_rows={len(normalized)}")
    print(f"valid_hosts={valid_hosts}")
    print(f"output={output_path}")


if __name__ == "__main__":
    main()
