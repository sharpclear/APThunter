"""Backward-compatible entry points for impersonation-domain detection.

The old system imported this module as ``phishing_detector``.  The actual
implementation now lives in ``impersonation_detector`` to avoid confusion with
phishing-domain detection, but keeping these aliases lets older task and
subscription code continue to work.
"""

try:
    from .impersonation_detector import (
        detect_impersonation_domains,
        predict_from_domains,
        predict_from_file,
        read_detection_domains_from_file,
        read_official_domains_from_file,
    )
except ImportError:  # pragma: no cover - direct import from models directory
    from impersonation_detector import (
        detect_impersonation_domains,
        predict_from_domains,
        predict_from_file,
        read_detection_domains_from_file,
        read_official_domains_from_file,
    )


def detect_phishing_domains(*args, **kwargs):
    return detect_impersonation_domains(*args, **kwargs)


__all__ = [
    "detect_impersonation_domains",
    "detect_phishing_domains",
    "predict_from_domains",
    "predict_from_file",
    "read_detection_domains_from_file",
    "read_official_domains_from_file",
]
