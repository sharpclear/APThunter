from __future__ import annotations

from typing import Sequence

import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin

try:
    from dga_features import FEATURE_COLUMNS, extract_dga_features
except ModuleNotFoundError:
    from .dga_features import FEATURE_COLUMNS, extract_dga_features


class DomainStatsTransformer(BaseEstimator, TransformerMixin):
    def fit(self, domains: Sequence[str], y: Sequence[int] | None = None):
        return self

    def transform(self, domains: Sequence[str]) -> np.ndarray:
        return np.asarray(
            [[features[column] for column in FEATURE_COLUMNS] for features in map(extract_dga_features, domains)],
            dtype=np.float32,
        )
