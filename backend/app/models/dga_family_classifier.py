#!/usr/bin/env python3
"""Utilities for DGA family classification."""

from __future__ import annotations

from typing import Sequence

import numpy as np


UNKNOWN_FAMILY = "unknown_family"


def normalize_family(value: object) -> str:
    """Return the primary family token used for supervised family labels."""

    tokens = [token.strip() for token in str(value or "").split(";") if token.strip()]
    if not tokens:
        return UNKNOWN_FAMILY
    for token in tokens:
        if token != "extrahop_unknown":
            return token
    return UNKNOWN_FAMILY


def predict_family_rows(
    bundle: dict[str, object],
    domains: Sequence[str],
    *,
    confidence_threshold: float | None = None,
    top_k: int = 3,
) -> list[dict[str, str]]:
    """Predict family rows from a fitted family classifier bundle."""

    if not domains:
        return []
    model = bundle["model"]
    threshold = float(
        confidence_threshold
        if confidence_threshold is not None
        else bundle.get("confidence_threshold", 0.60)
    )
    classes = list(getattr(model, "classes_", bundle.get("families", [])))
    probabilities = np.asarray(model.predict_proba(list(domains)), dtype=float)
    rows: list[dict[str, str]] = []
    for probs in probabilities:
        order = np.argsort(probs)[::-1]
        best_index = int(order[0])
        best_family = str(classes[best_index])
        best_confidence = float(probs[best_index])
        predicted_family = best_family if best_confidence >= threshold else UNKNOWN_FAMILY
        top_items = [
            f"{classes[int(index)]}:{float(probs[int(index)]):.6f}"
            for index in order[: max(1, top_k)]
        ]
        rows.append(
            {
                "top_family": best_family,
                "top_family_confidence": f"{best_confidence:.6f}",
                "predicted_family": predicted_family,
                "family_confidence": f"{best_confidence:.6f}",
                "family_top3": ";".join(top_items),
            }
        )
    return rows
