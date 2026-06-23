from __future__ import annotations

import os
import warnings
from pathlib import Path
from typing import Any, Sequence

import joblib
import numpy as np

try:
    from dga_features import (
        FEATURE_COLUMNS,
        build_rule_reasons,
        extract_dga_features,
        normalize_domain,
        split_domain,
    )
    from dga_word_features import wordlist_score
except ModuleNotFoundError:
    from .dga_features import (
        FEATURE_COLUMNS,
        build_rule_reasons,
        extract_dga_features,
        normalize_domain,
        split_domain,
    )
    from .dga_word_features import wordlist_score


CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_MODEL_PATH = os.path.join(CURRENT_DIR, "saved_model", "dga_binary_detector.joblib")
DEFAULT_BINARY_THRESHOLD = 0.90
DEFAULT_SUSPICIOUS_THRESHOLD = 0.35209923
DEFAULT_UNCERTAIN_THRESHOLD = 0.20

ScoreResult = dict[str, str]
_DETECTOR_CACHE: dict[str, "DgaBinaryDetector"] = {}


def _load_model_bundle(model_path: str | Path) -> dict[str, object]:
    try:
        bundle = joblib.load(model_path)
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            "DGA模型加载失败：缺少模型反序列化所需的 Python 模块或依赖"
        ) from exc
    except (AttributeError, ImportError, OSError, ValueError) as exc:
        raise RuntimeError(
            "DGA模型加载失败：请确认模型文件与当前 Python/scikit-learn 环境兼容"
        ) from exc
    if not isinstance(bundle, dict):
        raise RuntimeError("DGA模型加载失败：模型文件格式不正确")
    return bundle


def label_from_score(
    score: float,
    *,
    high_threshold: float = DEFAULT_BINARY_THRESHOLD,
    suspicious_threshold: float = DEFAULT_SUSPICIOUS_THRESHOLD,
    uncertain_threshold: float = DEFAULT_UNCERTAIN_THRESHOLD,
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


class DgaBinaryDetector:
    def __init__(
        self,
        model_path: str | Path = DEFAULT_MODEL_PATH,
        *,
        high_threshold: float | None = None,
        suspicious_threshold: float | None = None,
        uncertain_threshold: float | None = None,
    ) -> None:
        self.model_path = os.path.abspath(os.fspath(model_path))
        self.bundle = _load_model_bundle(self.model_path)
        bundle_thresholds = dict(self.bundle.get("thresholds", {}))
        self.high_threshold = float(
            high_threshold
            if high_threshold is not None
            else bundle_thresholds.get("high_confidence_dga", DEFAULT_BINARY_THRESHOLD)
        )
        self.suspicious_threshold = float(
            suspicious_threshold
            if suspicious_threshold is not None
            else bundle_thresholds.get("suspicious_dga", DEFAULT_SUSPICIOUS_THRESHOLD)
        )
        self.uncertain_threshold = float(
            uncertain_threshold
            if uncertain_threshold is not None
            else bundle_thresholds.get("uncertain", DEFAULT_UNCERTAIN_THRESHOLD)
        )

    def predict(self, domains: Sequence[str], *, include_debug: bool = False) -> list[ScoreResult]:
        normalized_domains = [normalize_domain(domain) for domain in domains]
        valid_domains = [domain for domain in normalized_domains if domain]
        if not valid_domains:
            return []

        scores = _predict_scores(self.bundle, valid_domains)
        results: list[ScoreResult] = []
        for domain, score in zip(valid_domains, scores):
            score_value = float(score)
            result = {
                "domain": domain,
                "dga_score": f"{score_value:.8f}",
                "is_dga": binary_label_from_score(score_value, threshold=self.high_threshold),
            }
            if include_debug:
                features = extract_dga_features(domain)
                result.update(
                    dga_label=label_from_score(
                        score_value,
                        high_threshold=self.high_threshold,
                        suspicious_threshold=self.suspicious_threshold,
                        uncertain_threshold=self.uncertain_threshold,
                    ),
                    reason=";".join(build_rule_reasons(features)),
                )
            results.append(result)
        return results

    def predict_one(self, domain: str, *, include_debug: bool = False) -> ScoreResult:
        results = self.predict([domain], include_debug=include_debug)
        return results[0] if results else {"domain": "", "dga_score": "", "is_dga": "0"}


def get_detector(model_path: str | Path = DEFAULT_MODEL_PATH, *, threshold: float | None = None) -> DgaBinaryDetector:
    resolved_model_path = os.path.abspath(os.fspath(model_path))
    cache_key = f"{resolved_model_path}:{threshold if threshold is not None else 'default'}"
    if cache_key not in _DETECTOR_CACHE:
        _DETECTOR_CACHE[cache_key] = DgaBinaryDetector(
            resolved_model_path,
            high_threshold=threshold,
        )
    return _DETECTOR_CACHE[cache_key]


def get_model_thresholds(
    model_path: str | Path = DEFAULT_MODEL_PATH,
    *,
    threshold: float | None = None,
) -> dict[str, float]:
    detector = get_detector(model_path, threshold=threshold)
    return {
        "high_confidence_dga": detector.high_threshold,
        "suspicious_dga": detector.suspicious_threshold,
        "uncertain": detector.uncertain_threshold,
    }


def score_raw_domains(
    *,
    raw_domains: Sequence[str],
    model_path: str | Path = DEFAULT_MODEL_PATH,
    threshold: float | None = None,
    domain_field_name: str = "domain",
    include_debug: bool = False,
) -> list[dict[str, Any]]:
    detector = get_detector(model_path, threshold=threshold)
    results = detector.predict(raw_domains, include_debug=include_debug)

    output_records: list[dict[str, Any]] = []
    for result in results:
        domain = result["domain"]
        score = float(result.get("dga_score") or 0.0)
        parts = split_domain(domain)
        record: dict[str, Any] = {
            domain_field_name: domain,
            "normalized_domain": domain,
            "model_input_text": parts.sld,
            "dga_like_score": f"{score:.6f}",
            "predicted_label": int(result.get("is_dga") == "1"),
        }
        if include_debug:
            record["dga_label"] = result.get("dga_label", "")
            record["reason"] = result.get("reason", "")
        output_records.append(record)
    return output_records


def _feature_matrix(domains: Sequence[str]) -> np.ndarray:
    return np.asarray(
        [[features[column] for column in FEATURE_COLUMNS] for features in map(extract_dga_features, domains)],
        dtype=np.float32,
    )


def _predict_scores(bundle: dict[str, object], domains: Sequence[str]) -> np.ndarray:
    model_name = str(bundle.get("model_name", "random_forest"))
    if model_name == "ensemble_wordlist_max":
        branches = bundle.get("branches", [])
        if not isinstance(branches, list) or not branches:
            raise ValueError("DGA ensemble model must contain non-empty branches")
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
