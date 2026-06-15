from __future__ import annotations

import json
import random
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import classification_report
    from sklearn.model_selection import train_test_split
    from sklearn.pipeline import Pipeline
except ImportError:
    TfidfVectorizer = None

from paper_data_layout import ML_WAF_DATA

from rfc_canonicalize import load_attack_benign_json, texts_from_requests


def _build_xy(
    attack_reqs: list[dict],
    benign_reqs: list[dict],
    canonical: bool,
    seed: int,
) -> tuple[list[str], list[int]]:
    xa = texts_from_requests(attack_reqs, canonical)
    xb = texts_from_requests(benign_reqs, canonical)
    texts = [(t, 1) for t in xa if t] + [(t, 0) for t in xb if t]
    random.Random(seed).shuffle(texts)
    if not texts:
        return [], []
    X = [a for a, _ in texts]
    y = [b for _, b in texts]
    return X, y


def eval_pipeline(
    X: list[str],
    y: list[int],
    seed: int,
) -> dict[str, Any]:
    if TfidfVectorizer is None or not X:
        return {"error": "need scikit-learn and non-empty data", "n": len(X)}
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.35, random_state=seed, stratify=y if len(set(y)) > 1 else None
    )
    pipe = Pipeline(
        [
            ("tfidf", TfidfVectorizer(max_features=4096, ngram_range=(1, 2))),
            ("lr", LogisticRegression(max_iter=2000, random_state=seed)),
        ]
    )
    pipe.fit(X_train, y_train)
    pred = pipe.predict(X_test)
    rep = classification_report(y_test, pred, output_dict=True, zero_division=0)
    return {
        "n_total": len(X),
        "n_train": len(X_train),
        "n_test": len(X_test),
        "accuracy": float(sum(int(a == b) for a, b in zip(y_test, pred)) / len(y_test)) if y_test else 0.0,
        "classification_report": rep,
    }


def defense_comparison_report(
    data_dir: Path | None = None,
    seed: int = 42,
) -> dict[str, Any]:
    root = data_dir or ML_WAF_DATA
    attack, benign = load_attack_benign_json(root)
    raw = _build_xy(attack, benign, canonical=False, seed=seed)
    canon = _build_xy(attack, benign, canonical=True, seed=seed)
    out: dict[str, Any] = {
        "data_dir": str(root.resolve()),
        "n_attack_requests": len(attack),
        "n_benign_requests": len(benign),
    }
    if raw[0]:
        out["ml_on_raw_strings"] = eval_pipeline(raw[0], raw[1], seed=seed)
    else:
        out["ml_on_raw_strings"] = {"skipped": True}
    if canon[0]:
        out["ml_on_rfc_canonicalized_strings"] = eval_pipeline(canon[0], canon[1], seed=seed)
    else:
        out["ml_on_rfc_canonicalized_strings"] = {"skipped": True}
    out["methodology"] = {
        "defense_track": "rfc_canonicalize_then_ml_baseline",
        "canonicalization": "urllib.parse.unquote_plus repeated until fixpoint (see rfc_canonicalize.unquote_chain)",
        "note": "Small public-style attack/benign JSON; extend with larger labeled HTTP captures for paper experiments.",
    }
    return out


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")
