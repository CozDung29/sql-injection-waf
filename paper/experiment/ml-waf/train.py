import json
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix

from features import extract, FEATURE_NAMES

DATA_DIR = Path(__file__).resolve().parent / "data"
MODEL_DIR = Path(__file__).resolve().parent / "models"
MODEL_PATH = MODEL_DIR / "waf_model.joblib"


def payload_to_request(payload: str, param: str = "id") -> dict:
    return {
        "method": "GET",
        "path": "/api",
        "query": f"{param}={payload}",
        "headers": {},
        "body": "",
    }


def load_all_data():
    benign_reqs = []
    attack_reqs = []

    benign_path = DATA_DIR / "benign.json"
    if benign_path.exists():
        with open(benign_path, "r", encoding="utf-8") as f:
            benign_reqs.extend(json.load(f))

    attack_path = DATA_DIR / "attack.json"
    if attack_path.exists():
        with open(attack_path, "r", encoding="utf-8") as f:
            attack_reqs.extend(json.load(f))

    bypass_learned = DATA_DIR / "bypass_learned.jsonl"
    if bypass_learned.exists():
        with open(bypass_learned, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                obj = json.loads(line)
                payload = obj.get("payload", "")
                if payload:
                    attack_reqs.append(payload_to_request(payload, "account"))

    blocked_learned = DATA_DIR / "blocked_learned.jsonl"
    if blocked_learned.exists():
        with open(blocked_learned, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                obj = json.loads(line)
                payload = obj.get("payload", "")
                if payload:
                    attack_reqs.append(payload_to_request(payload, "account"))

    bypass_dataset = DATA_DIR / "bypass_dataset.json"
    if bypass_dataset.exists():
        with open(bypass_dataset, "r", encoding="utf-8") as f:
            rows = json.load(f)
        for row in rows:
            payload = row.get("transformed", "")
            if payload:
                attack_reqs.append(payload_to_request(payload))

    return benign_reqs, attack_reqs


def main():
    MODEL_DIR.mkdir(exist_ok=True)
    benign_reqs, attack_reqs = load_all_data()

    n_benign = len(benign_reqs)
    n_attack = len(attack_reqs)
    min_benign = min(500, n_attack // 2)
    if n_benign > 0 and n_benign < min_benign:
        repeat = (min_benign + n_benign - 1) // n_benign
        benign_reqs = (benign_reqs * repeat)[:min_benign]
        n_benign = len(benign_reqs)
    print(f"Benign: {n_benign}, Attack: {n_attack}")

    if n_benign == 0 or n_attack == 0:
        raise SystemExit("Need both benign and attack samples. Add data to benign.json and/or run evasion to collect attacks.")

    X_benign = [extract(r) for r in benign_reqs]
    X_attack = [extract(r) for r in attack_reqs]
    X = np.array(X_benign + X_attack)
    y = np.array([0] * n_benign + [1] * n_attack)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )
    clf = RandomForestClassifier(
        n_estimators=100, random_state=42, max_depth=10, class_weight="balanced"
    )
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)
    print(classification_report(y_test, y_pred, target_names=["benign", "attack"]))
    print(confusion_matrix(y_test, y_pred))
    joblib.dump({"model": clf, "feature_names": FEATURE_NAMES}, MODEL_PATH)
    print("Model saved to", MODEL_PATH)


if __name__ == "__main__":
    main()
