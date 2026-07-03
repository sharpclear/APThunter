"""Compatibility shim for sklearn model bundles persisted with top-level _loss."""

from sklearn._loss._loss import CyHalfBinomialLoss

__all__ = ["CyHalfBinomialLoss"]
