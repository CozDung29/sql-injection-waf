import json
import sys
from pathlib import Path

from predict import predict_request, load_model

DATA_DIR = Path(__file__).resolve().parent / "data"
MODEL_PATH = Path(__file__).resolve().parent / "models" / "waf_model.joblib"


def run_tests():
    if not MODEL_PATH.exists():
        print("Model not found. Run: python train.py")
        sys.exit(1)
    model, _ = load_model()
    with open(DATA_DIR / "benign.json", "r", encoding="utf-8") as f:
        benign = json.load(f)
    with open(DATA_DIR / "attack.json", "r", encoding="utf-8") as f:
        attack = json.load(f)
    ok = 0
    total = 0
    print("--- Benign (expect: benign) ---")
    for i, req in enumerate(benign):
        pred, score = predict_request(req, model)
        label = "attack" if pred == 1 else "benign"
        total += 1
        if pred == 0:
            ok += 1
        print(f"  [{i+1}] {label} (score={score:.3f}) {'OK' if pred == 0 else 'FAIL'}")
    print("--- Attack (expect: attack) ---")
    for i, req in enumerate(attack):
        pred, score = predict_request(req, model)
        label = "attack" if pred == 1 else "benign"
        total += 1
        if pred == 1:
            ok += 1
        print(f"  [{i+1}] {label} (score={score:.3f}) {'OK' if pred == 1 else 'FAIL'}")
    print(f"\nResult: {ok}/{total} passed")
    return ok == total


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
