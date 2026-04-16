import json
import sys
from pathlib import Path

import joblib

from features import extract

MODEL_PATH = Path(__file__).resolve().parent / "models" / "waf_model.joblib"


def load_model():
    payload = joblib.load(MODEL_PATH)
    return payload["model"], payload.get("feature_names")


def predict_request(req: dict, model=None):
    if model is None:
        model, _ = load_model()
    x = [extract(req)]
    proba = model.predict_proba(x)[0]
    pred = model.predict(x)[0]
    return int(pred), float(proba[1])


def main():
    if not MODEL_PATH.exists():
        print("Run train.py first to create the model.", file=sys.stderr)
        sys.exit(1)
    model, _ = load_model()
    if len(sys.argv) > 1:
        with open(sys.argv[1], "r", encoding="utf-8") as f:
            req = json.load(f)
    else:
        req = json.load(sys.stdin)
    pred, score = predict_request(req, model)
    out = {"label": "attack" if pred == 1 else "benign", "score": score}
    print(json.dumps(out))


if __name__ == "__main__":
    main()
