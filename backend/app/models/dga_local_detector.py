#!/usr/bin/env python3
"""Score domains with a trained DGA-like classifier."""

from __future__ import annotations

import argparse
import csv
import sys
import warnings
from pathlib import Path
from typing import Sequence

import joblib
import numpy as np

try:
    from sklearn.exceptions import InconsistentVersionWarning

    warnings.filterwarnings("ignore", category=InconsistentVersionWarning)
except Exception:  # pragma: no cover - sklearn compatibility guard
    pass

try:
    from dga_family_classifier import predict_family_rows
    from dga_family_sequence_classifier import predict_sequence_family_rows
    from dga_features import FEATURE_COLUMNS, build_rule_reasons, extract_dga_features, normalize_domain
    from dga_word_features import wordlist_score
except ModuleNotFoundError:
    from .dga_family_classifier import predict_family_rows
    from .dga_family_sequence_classifier import predict_sequence_family_rows
    from .dga_features import FEATURE_COLUMNS, build_rule_reasons, extract_dga_features, normalize_domain
    from .dga_word_features import wordlist_score


CURRENT_DIR = Path(__file__).resolve().parent
DEFAULT_PACKAGE_DIR = CURRENT_DIR / "saved_model" / "dga_detection_local_model"
DEFAULT_MODEL = DEFAULT_PACKAGE_DIR / "models" / "model_dga_detector.joblib"
DEFAULT_OUTPUT = DEFAULT_PACKAGE_DIR / "data" / "holdout" / "dga_scores.csv"
DEFAULT_FAMILY_MODEL = (
    DEFAULT_PACKAGE_DIR
    / "models"
    / "family_sequence_gru_public_sources_user_approved"
    / "model_dga_family_sequence_gru.pt"
)
DEFAULT_FAMILY_AUDIT = (
    DEFAULT_PACKAGE_DIR
    / "data"
    / "holdout"
    / "family_attribution_audit_sequence_gru_default_threshold_0p98"
    / "family_attribution_audit_by_family.csv"
)
DEFAULT_FAMILY_CONFIDENCE_THRESHOLD = 0.95
DEFAULT_FAMILY_INPUT_THRESHOLD = 0.90
DEFAULT_DIRECT_HIGH_CONFIDENCE_THRESHOLD = 0.98
ScoreResult = dict[str, str]
SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))


def _load_model_bundle(model_path: str | Path) -> dict[str, object]:
    try:
        return joblib.load(model_path)
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            "failed to load the DGA model bundle because a Python module is missing; "
            "install requirements.txt in the same Python environment used for scoring"
        ) from exc
    except (AttributeError, ImportError, OSError) as exc:
        raise RuntimeError(
            "failed to load the DGA model bundle; ensure the model was built for this Python/scikit-learn "
            "environment or rebuild it with scripts/build_dga_ensemble_model.py"
        ) from exc


def _load_family_model_bundle(model_path: str | Path) -> dict[str, object]:
    path = Path(model_path)
    if path.suffix in {".pt", ".pth"}:
        try:
            import torch
        except ModuleNotFoundError as exc:
            raise RuntimeError(
                "failed to load the DGA family sequence model because torch is missing; "
                "install torch in the scoring environment or use the joblib family model"
            ) from exc
        try:
            return torch.load(path, map_location="cpu", weights_only=False)
        except TypeError:
            return torch.load(path, map_location="cpu")
    return _load_model_bundle(path)


def _predict_family_rows_for_bundle(
    bundle: dict[str, object],
    domains: Sequence[str],
    *,
    confidence_threshold: float | None = None,
) -> list[ScoreResult]:
    if str(bundle.get("model_name", "")) == "dga_family_sequence_gru":
        return predict_sequence_family_rows(
            bundle,
            domains,
            confidence_threshold=confidence_threshold,
        )
    return predict_family_rows(
        bundle,
        domains,
        confidence_threshold=confidence_threshold,
    )


def label_from_score(
    score: float,
    *,
    high_threshold: float = 0.98,
    suspicious_threshold: float = 0.90,
    uncertain_threshold: float = 0.70,
) -> str:
    if score >= high_threshold:
        return "high_confidence_dga"
    if score >= suspicious_threshold:
        return "suspicious_dga"
    if score >= uncertain_threshold:
        return "uncertain"
    return "non_dga_like"


def binary_label_from_score(score: float, *, threshold: float) -> str:
    return "1" if score >= threshold else "0"


def _load_family_audit(path: str | Path | None) -> dict[str, str]:
    if not path:
        return {}
    audit_path = Path(path)
    if not audit_path.exists():
        raise FileNotFoundError(f"family audit file does not exist: {audit_path}")
    with audit_path.open(newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        required = {"predicted_family", "audit_status"}
        missing = required.difference(reader.fieldnames or [])
        if missing:
            raise ValueError(f"family audit CSV missing required columns: {', '.join(sorted(missing))}")
        return {
            row["predicted_family"].strip(): row["audit_status"].strip()
            for row in reader
            if row.get("predicted_family") and row.get("audit_status")
        }


def _apply_family_attribution_status(row: ScoreResult, family_audit: dict[str, str]) -> ScoreResult:
    family = row.get("predicted_family", "")
    if not family:
        row["family_attribution_status"] = ""
        return row
    if family == "unknown_family":
        row["family_attribution_status"] = "unknown_family"
        return row
    if not family_audit:
        row["family_attribution_status"] = "not_audited"
        return row

    status = family_audit.get(family, "not_audited")
    row["family_attribution_status"] = status
    if status == "usable":
        return row
    if status.startswith("caution_"):
        row["predicted_family"] = "possible_family"
    else:
        row["predicted_family"] = "unknown_family"
    return row


def _has_promotable_family_attribution(row: ScoreResult, *, require_usable_status: bool) -> bool:
    family = row.get("predicted_family", "")
    if family in {"", "unknown_family", "possible_family"}:
        return False
    status = row.get("family_attribution_status", "")
    if require_usable_status:
        return status == "usable"
    return status in {"", "not_audited", "usable"}


def _family_attribution_display_rank(row: ScoreResult) -> int:
    family = row.get("predicted_family", "")
    status = row.get("family_attribution_status", "")
    if status == "usable" and family not in {"", "unknown_family", "possible_family"}:
        return 0
    if family == "possible_family" or status.startswith("caution_"):
        return 1
    if family and family != "unknown_family":
        return 2
    if family == "unknown_family":
        return 3
    return 4


def _dga_label_display_rank(row: ScoreResult) -> int:
    label = row.get("dga_label", "")
    ranks = {
        "high_confidence_dga": 0,
        "suspicious_dga": 1,
        "uncertain": 2,
        "non_dga_like": 3,
    }
    return ranks.get(label, 4)


def _score_display_value(row: ScoreResult) -> float:
    try:
        return float(row.get("dga_score", ""))
    except ValueError:
        return 0.0


def _sort_rows_for_family_attribution_display(rows: Sequence[ScoreResult]) -> list[ScoreResult]:
    indexed_rows = list(enumerate(rows))
    indexed_rows.sort(
        key=lambda item: (
            _family_attribution_display_rank(item[1]),
            _dga_label_display_rank(item[1]),
            -_score_display_value(item[1]),
            item[0],
        )
    )
    return [row for _, row in indexed_rows]


class DgaDetector:
    """Reusable local DGA detector for system integration."""

    def __init__(
        self,
        model_path: str | Path = DEFAULT_MODEL,
        *,
        family_model_path: str | Path | None = None,
        family_audit_path: str | Path | None = None,
        high_threshold: float | None = None,
        suspicious_threshold: float | None = None,
        uncertain_threshold: float | None = None,
        family_input_threshold: float | None = None,
        family_confidence_threshold: float | None = None,
        promote_family_attribution_to_high_confidence: bool = False,
    ) -> None:
        self.bundle = _load_model_bundle(model_path)
        self.family_bundle = _load_family_model_bundle(family_model_path) if family_model_path else None
        self.family_audit = _load_family_audit(family_audit_path) if family_model_path else {}
        self.family_confidence_threshold = family_confidence_threshold
        self.promote_family_attribution_to_high_confidence = promote_family_attribution_to_high_confidence
        bundle_thresholds = dict(self.bundle.get("thresholds", {}))
        self.suspicious_threshold = float(
            suspicious_threshold if suspicious_threshold is not None else bundle_thresholds.get("suspicious_dga", 0.90)
        )
        self.uncertain_threshold = float(
            uncertain_threshold if uncertain_threshold is not None else bundle_thresholds.get("uncertain", 0.70)
        )
        self.family_input_threshold = float(
            family_input_threshold
            if family_input_threshold is not None
            else bundle_thresholds.get(
                "family_input_dga",
                bundle_thresholds.get("suspicious_dga", DEFAULT_FAMILY_INPUT_THRESHOLD),
            )
        )
        direct_high_threshold = bundle_thresholds.get("direct_high_confidence_dga")
        legacy_high_threshold = bundle_thresholds.get("high_confidence_dga")
        if high_threshold is not None:
            self.high_threshold = float(high_threshold)
        elif direct_high_threshold is not None:
            self.high_threshold = float(direct_high_threshold)
        elif legacy_high_threshold is not None and float(legacy_high_threshold) > self.family_input_threshold:
            self.high_threshold = float(legacy_high_threshold)
        else:
            self.high_threshold = DEFAULT_DIRECT_HIGH_CONFIDENCE_THRESHOLD

    def predict(self, domains: Sequence[str], *, include_debug: bool = False) -> list[ScoreResult]:
        normalized_domains = [normalize_domain(domain) for domain in domains]
        valid_domains = [domain for domain in normalized_domains if domain]
        scores = _predict_scores(self.bundle, valid_domains)
        family_rows_by_domain: dict[str, ScoreResult] = {}
        if self.family_bundle is not None:
            family_input_domains = [
                domain
                for domain, score in zip(valid_domains, scores)
                if binary_label_from_score(float(score), threshold=self.family_input_threshold) == "1"
            ]
            family_predictions = _predict_family_rows_for_bundle(
                self.family_bundle,
                family_input_domains,
                confidence_threshold=self.family_confidence_threshold,
            )
            family_rows_by_domain = dict(zip(family_input_domains, family_predictions))
        results: list[ScoreResult] = []
        for domain, score in zip(valid_domains, scores):
            score_value = float(score)
            result = {
                "domain": domain,
                "dga_score": f"{score_value:.8f}",
                "is_dga": binary_label_from_score(score_value, threshold=self.suspicious_threshold),
            }
            if self.family_bundle is not None:
                result.update(
                    family_rows_by_domain.get(
                        domain,
                        {
                            "top_family": "",
                            "top_family_confidence": "",
                            "predicted_family": "",
                            "family_confidence": "",
                            "family_top3": "",
                            "family_attribution_status": "",
                        },
                    )
                )
                result = _apply_family_attribution_status(result, self.family_audit)
            if include_debug:
                features = extract_dga_features(domain)
                dga_label = label_from_score(
                    score_value,
                    high_threshold=self.high_threshold,
                    suspicious_threshold=self.suspicious_threshold,
                    uncertain_threshold=self.uncertain_threshold,
                )
                family_promoted = (
                    self.promote_family_attribution_to_high_confidence
                    and dga_label != "high_confidence_dga"
                    and score_value >= self.family_input_threshold
                    and _has_promotable_family_attribution(
                        result,
                        require_usable_status=bool(self.family_audit),
                    )
                )
                reasons = build_rule_reasons(features)
                if family_promoted:
                    dga_label = "high_confidence_dga"
                    result["is_dga"] = "1"
                result.update(
                    dga_label=dga_label,
                    reason=";".join(reasons),
                )
            results.append(result)
        return results

    def predict_one(self, domain: str, *, include_debug: bool = False) -> ScoreResult:
        results = self.predict([domain], include_debug=include_debug)
        return results[0] if results else {"domain": "", "dga_score": "", "is_dga": "0"}


def _feature_matrix(domains: Sequence[str]) -> np.ndarray:
    return np.asarray(
        [[features[column] for column in FEATURE_COLUMNS] for features in map(extract_dga_features, domains)],
        dtype=np.float32,
    )


def _looks_like_domain_value(value: str) -> bool:
    normalized = normalize_domain(value)
    return bool(normalized and "." in normalized and " " not in normalized)


def _read_input_rows(path: str | Path, *, domain_column: str = "domain") -> tuple[list[dict[str, str]], list[str]]:
    rows: list[dict[str, str]] = []
    path = Path(path)
    with path.open(newline="", encoding="utf-8-sig") as f:
        preview_reader = csv.reader(f)
        preview_rows = [row for _, row in zip(range(5), preview_reader) if row]

    if not preview_rows:
        return rows, [domain_column]

    first_row = [cell.strip() for cell in preview_rows[0]]
    header_lookup = {name.lower(): idx for idx, name in enumerate(first_row)}
    domain_column_key = domain_column.lower()
    if domain_column_key in header_lookup:
        fieldnames = list(first_row)
        domain_index = header_lookup[domain_column_key]
        fieldnames[domain_index] = domain_column
        with path.open(newline="", encoding="utf-8-sig") as f:
            reader = csv.reader(f)
            next(reader, None)
            for raw_row in reader:
                if not raw_row:
                    continue
                padded_row = list(raw_row[: len(fieldnames)]) + [""] * max(0, len(fieldnames) - len(raw_row))
                row = {fieldname: padded_row[idx] for idx, fieldname in enumerate(fieldnames)}
                domain = normalize_domain(padded_row[domain_index] if domain_index < len(padded_row) else "")
                if domain:
                    row[domain_column] = domain
                    rows.append(row)
        return rows, fieldnames

    first_value = first_row[0] if first_row else ""
    if not _looks_like_domain_value(first_value) and any(
        _looks_like_domain_value(row[0].strip()) for row in preview_rows[1:] if row and row[0].strip()
    ):
        raise ValueError(f"input CSV must contain {domain_column!r}")

    with path.open(newline="", encoding="utf-8-sig") as f:
        reader = csv.reader(f)
        for raw_row in reader:
            if not raw_row:
                continue
            domain = normalize_domain(raw_row[0])
            if domain:
                rows.append({domain_column: domain})
    return rows, [domain_column]


def _predict_scores(bundle: dict[str, object], domains: Sequence[str]) -> np.ndarray:
    model_name = str(bundle.get("model_name", "random_forest"))
    if model_name == "ensemble_wordlist_max":
        branches = bundle.get("branches", [])
        if not isinstance(branches, list) or not branches:
            raise ValueError("ensemble_wordlist_max bundle must contain non-empty branches")
        branch_scores: list[np.ndarray] = []
        for branch in branches:
            branch_model = branch["model"]
            branch_name = str(branch.get("model_name", ""))
            if branch_name in {"tfidf_logistic", "hybrid_lightgbm", "hybrid_logistic", "hybrid_sgd"}:
                branch_matrix = list(domains)
            else:
                branch_matrix = _feature_matrix(domains)
            if hasattr(branch_model, "predict_proba"):
                scores = np.asarray(branch_model.predict_proba(branch_matrix)[:, 1], dtype=float)
            else:
                decision = np.asarray(branch_model.decision_function(branch_matrix), dtype=float)
                scores = 1.0 / (1.0 + np.exp(-decision))
            branch_scores.append(float(branch.get("weight", 1.0)) * scores)
        word_config = dict(bundle.get("wordlist", {}))
        words = frozenset(word_config.get("words", []))
        word_scores = np.asarray(
            [
                wordlist_score(
                    domain,
                    words,
                    len_center=float(word_config.get("len_center", 26.0)),
                    count_center=float(word_config.get("count_center", 6.0)),
                    coverage_center=float(word_config.get("coverage_center", 0.85)),
                )
                for domain in domains
            ],
            dtype=float,
        )
        branch_scores.append(word_scores)
        return np.maximum.reduce(branch_scores)
    model = bundle["model"]
    if model_name in {"tfidf_logistic", "hybrid_lightgbm", "hybrid_logistic", "hybrid_sgd"}:
        matrix = list(domains)
    else:
        matrix = _feature_matrix(domains)
    # Feature order is fixed by FEATURE_COLUMNS, so the sklearn feature-name warning
    # is not actionable for ndarray inference against the bundled local model.
    with warnings.catch_warnings():
        warnings.filterwarnings(
            "ignore",
            message=r"X does not have valid feature names, but .* was fitted with feature names",
            category=UserWarning,
        )
        if hasattr(model, "predict_proba"):
            return np.asarray(model.predict_proba(matrix)[:, 1], dtype=float)
        decision = np.asarray(model.decision_function(matrix), dtype=float)
    return 1.0 / (1.0 + np.exp(-decision))


def score_domains(
    *,
    model_path: str | Path,
    input_path: str | Path,
    output_path: str | Path,
    family_model_path: str | Path | None = None,
    family_audit_path: str | Path | None = None,
    domain_column: str = "domain",
    high_threshold: float | None = None,
    suspicious_threshold: float | None = None,
    uncertain_threshold: float | None = None,
    family_input_threshold: float | None = None,
    family_confidence_threshold: float | None = None,
    prioritize_family_attribution: bool = False,
    promote_family_attribution_to_high_confidence: bool = False,
) -> int:
    detector = DgaDetector(
        model_path,
        family_model_path=family_model_path,
        family_audit_path=family_audit_path,
        high_threshold=high_threshold,
        suspicious_threshold=suspicious_threshold,
        uncertain_threshold=uncertain_threshold,
        family_input_threshold=family_input_threshold,
        family_confidence_threshold=family_confidence_threshold,
        promote_family_attribution_to_high_confidence=promote_family_attribution_to_high_confidence,
    )
    input_rows, input_fieldnames = _read_input_rows(input_path, domain_column=domain_column)
    domains = [row[domain_column] for row in input_rows]
    results = detector.predict(domains, include_debug=True)
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    model_fields = {
        "dga_score",
        "is_dga",
        "dga_label",
        "reason",
        "top_family",
        "top_family_confidence",
        "predicted_family",
        "family_confidence",
        "family_top3",
        "family_attribution_status",
    }
    output_fields = [field for field in input_fieldnames if field not in model_fields]
    output_fields.extend(["dga_score", "is_dga", "dga_label", "reason"])
    if family_model_path:
        output_fields.extend(
            [
                "top_family",
                "top_family_confidence",
                "predicted_family",
                "family_confidence",
                "family_top3",
                "family_attribution_status",
            ]
        )
    with output_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=output_fields)
        writer.writeheader()
        output_rows: list[ScoreResult] = []
        for row, result in zip(input_rows, results):
            output_row = dict(row)
            output_row.update(result)
            output_rows.append({field: output_row.get(field, "") for field in output_fields})
        if prioritize_family_attribution:
            output_rows = _sort_rows_for_family_attribution_display(output_rows)
        writer.writerows(output_rows)
    return len(domains)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", type=Path, default=DEFAULT_MODEL)
    parser.add_argument("--family-model", type=Path, default=DEFAULT_FAMILY_MODEL)
    parser.add_argument("--family-audit", type=Path, default=DEFAULT_FAMILY_AUDIT)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--domain-column", default="domain")
    parser.add_argument("--high-threshold", type=float)
    parser.add_argument("--suspicious-threshold", type=float)
    parser.add_argument("--uncertain-threshold", type=float)
    parser.add_argument("--family-input-threshold", type=float, default=DEFAULT_FAMILY_INPUT_THRESHOLD)
    parser.add_argument("--family-confidence-threshold", type=float, default=DEFAULT_FAMILY_CONFIDENCE_THRESHOLD)
    parser.add_argument(
        "--prioritize-family-attribution",
        action="store_true",
        help="sort CSV output for review: usable/possible family attribution first, then DGA label, then score",
    )
    parser.add_argument(
        "--promote-family-attribution-to-high-confidence",
        action="store_true",
        help=(
            "label lower-threshold DGA pool rows as high_confidence_dga when the family model returns a concrete "
            "family attribution; when a family audit file is supplied, only audit_status=usable is promoted"
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    count = score_domains(
        model_path=args.model,
        input_path=args.input,
        output_path=args.output,
        family_model_path=args.family_model,
        family_audit_path=args.family_audit,
        domain_column=args.domain_column,
        high_threshold=args.high_threshold,
        suspicious_threshold=args.suspicious_threshold,
        uncertain_threshold=args.uncertain_threshold,
        family_input_threshold=args.family_input_threshold,
        family_confidence_threshold=args.family_confidence_threshold,
        prioritize_family_attribution=args.prioritize_family_attribution,
        promote_family_attribution_to_high_confidence=args.promote_family_attribution_to_high_confidence,
    )
    print(f"scored_rows={count} output={args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
