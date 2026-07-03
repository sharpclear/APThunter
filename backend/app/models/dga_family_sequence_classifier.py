#!/usr/bin/env python3
"""Character sequence model utilities for DGA family attribution."""

from __future__ import annotations

from typing import Sequence

import numpy as np

try:
    import torch
    from torch import nn
    from torch.utils.data import Dataset

    TORCH_AVAILABLE = True
except ModuleNotFoundError:  # pragma: no cover - environment guarded
    torch = None
    nn = None
    Dataset = object
    TORCH_AVAILABLE = False

try:
    from dga_family_classifier import UNKNOWN_FAMILY
    from dga_features import normalize_domain
except ModuleNotFoundError:
    from .dga_family_classifier import UNKNOWN_FAMILY
    from .dga_features import normalize_domain


def require_torch() -> None:
    if not TORCH_AVAILABLE or torch is None or nn is None:
        raise RuntimeError("torch is required for the DGA family sequence classifier")


def build_family_label_maps(families: Sequence[str]) -> tuple[list[str], dict[str, int]]:
    """Return stable family labels and index mapping."""

    labels = sorted({str(family).strip() for family in families if str(family).strip()})
    return labels, {family: index for index, family in enumerate(labels)}


def build_char_vocab(domains: Sequence[str]) -> dict[str, int]:
    vocab = {"<pad>": 0, "<unk>": 1}
    for char in sorted(set("".join(normalize_domain(domain) for domain in domains))):
        if char and char not in vocab:
            vocab[char] = len(vocab)
    return vocab


def encode_domains(domains: Sequence[str], vocab: dict[str, int], *, max_length: int) -> np.ndarray:
    encoded = np.zeros((len(domains), max_length), dtype=np.int64)
    for row_index, domain in enumerate(domains):
        normalized = normalize_domain(domain)
        for col_index, char in enumerate(normalized[:max_length]):
            encoded[row_index, col_index] = vocab.get(char, 1)
    return encoded


class FamilySequenceDataset(Dataset):
    def __init__(self, sequences: np.ndarray, labels: np.ndarray):
        require_torch()
        self.sequences = torch.as_tensor(sequences, dtype=torch.long)
        self.labels = torch.as_tensor(labels, dtype=torch.long)

    def __len__(self) -> int:
        return int(self.labels.shape[0])

    def __getitem__(self, index: int):
        return self.sequences[index], self.labels[index]


if TORCH_AVAILABLE:

    class FamilySequenceGruClassifier(nn.Module):
        """Small GRU classifier for known DGA family labels."""

        def __init__(self, *, vocab_size: int, embedding_size: int, hidden_size: int, family_count: int):
            super().__init__()
            self.embedding = nn.Embedding(vocab_size, embedding_size, padding_idx=0)
            self.gru = nn.GRU(embedding_size, hidden_size, batch_first=True)
            self.classifier = nn.Linear(hidden_size, family_count)

        def forward(self, sequences):
            lengths = sequences.ne(0).sum(dim=1).clamp(min=1).cpu()
            embedded = self.embedding(sequences)
            packed = nn.utils.rnn.pack_padded_sequence(
                embedded,
                lengths,
                batch_first=True,
                enforce_sorted=False,
            )
            outputs, hidden = self.gru(packed)
            features = hidden[-1] if hidden is not None else outputs[:, -1, :]
            return self.classifier(features)

else:

    class FamilySequenceGruClassifier:  # pragma: no cover - environment guarded
        def __init__(self, *args, **kwargs):
            require_torch()


def build_sequence_family_bundle(
    *,
    model: FamilySequenceGruClassifier,
    vocab: dict[str, int],
    families: Sequence[str],
    max_length: int,
    embedding_size: int,
    hidden_size: int,
    confidence_threshold: float,
) -> dict[str, object]:
    require_torch()
    return {
        "model_name": "dga_family_sequence_gru",
        "state_dict": model.state_dict(),
        "vocab": dict(vocab),
        "families": list(families),
        "max_length": int(max_length),
        "embedding_size": int(embedding_size),
        "hidden_size": int(hidden_size),
        "confidence_threshold": float(confidence_threshold),
        "unknown_family": UNKNOWN_FAMILY,
    }


def load_sequence_family_model(bundle: dict[str, object], *, device: str = "cpu"):
    require_torch()
    families = list(bundle["families"])
    model = FamilySequenceGruClassifier(
        vocab_size=len(bundle["vocab"]),
        embedding_size=int(bundle["embedding_size"]),
        hidden_size=int(bundle["hidden_size"]),
        family_count=len(families),
    ).to(device)
    model.load_state_dict(bundle["state_dict"])
    model.eval()
    return model


def predict_sequence_family_probabilities(
    bundle: dict[str, object],
    domains: Sequence[str],
    *,
    batch_size: int = 512,
    device: str = "cpu",
) -> np.ndarray:
    require_torch()
    if not domains:
        return np.asarray([], dtype=np.float32).reshape(0, len(bundle.get("families", [])))
    model = load_sequence_family_model(bundle, device=device)
    sequences = encode_domains(domains, bundle["vocab"], max_length=int(bundle["max_length"]))
    outputs: list[np.ndarray] = []
    with torch.no_grad():
        for start in range(0, len(domains), batch_size):
            batch_sequences = torch.as_tensor(sequences[start : start + batch_size], dtype=torch.long, device=device)
            logits = model(batch_sequences)
            outputs.append(torch.softmax(logits, dim=1).cpu().numpy())
    return np.concatenate(outputs, axis=0) if outputs else np.asarray([], dtype=np.float32)


def predict_sequence_family_rows(
    bundle: dict[str, object],
    domains: Sequence[str],
    *,
    confidence_threshold: float | None = None,
    top_k: int = 3,
    batch_size: int = 512,
    device: str = "cpu",
) -> list[dict[str, str]]:
    """Predict family rows from a fitted sequence classifier bundle."""

    if not domains:
        return []
    families = list(bundle["families"])
    threshold = float(
        confidence_threshold if confidence_threshold is not None else bundle.get("confidence_threshold", 0.60)
    )
    probabilities = predict_sequence_family_probabilities(bundle, domains, batch_size=batch_size, device=device)
    rows: list[dict[str, str]] = []
    for probs in probabilities:
        order = np.argsort(probs)[::-1]
        best_index = int(order[0])
        best_family = str(families[best_index])
        best_confidence = float(probs[best_index])
        predicted_family = best_family if best_confidence >= threshold else UNKNOWN_FAMILY
        top_items = [
            f"{families[int(index)]}:{float(probs[int(index)]):.6f}"
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


def build_sequence_training_inputs(
    domains: Sequence[str],
    families: Sequence[str],
    *,
    max_length: int,
) -> tuple[np.ndarray, np.ndarray, dict[str, int], list[str], dict[str, int]]:
    family_labels, label_to_index = build_family_label_maps(families)
    vocab = build_char_vocab(domains)
    sequences = encode_domains(domains, vocab, max_length=max_length)
    labels = np.asarray([label_to_index[family] for family in families], dtype=np.int64)
    return sequences, labels, vocab, family_labels, label_to_index
