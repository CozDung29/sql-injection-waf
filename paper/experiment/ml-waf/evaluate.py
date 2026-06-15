import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from predict import predict_request, load_model
from train import payload_to_request

DATA_DIR = Path(__file__).resolve().parent / "data"
MODEL_PATH = Path(__file__).resolve().parent / "models" / "waf_model.joblib"
OUT_REPORT = DATA_DIR / "evaluation_report.json"
OUT_BYPASS_UPDATED = DATA_DIR / "bypass_dataset_scored.json"


def load_datasets_separately() -> list[tuple[list, int, str]]:
    out = []
    if (DATA_DIR / "benign.json").exists():
        with open(DATA_DIR / "benign.json", "r", encoding="utf-8") as f:
            reqs = json.load(f)
        out.append((reqs, 0, "benign.json"))
    if (DATA_DIR / "attack.json").exists():
        with open(DATA_DIR / "attack.json", "r", encoding="utf-8") as f:
            reqs = json.load(f)
        out.append((reqs, 1, "attack.json"))
    for fname, param in [("bypass_learned.jsonl", "account"), ("blocked_learned.jsonl", "account")]:
        path = DATA_DIR / fname
        if path.exists():
            reqs = []
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    obj = json.loads(line)
                    p = obj.get("payload", "")
                    if p:
                        reqs.append(payload_to_request(p, param))
            out.append((reqs, 1, fname))
    if (DATA_DIR / "bypass_dataset.json").exists():
        with open(DATA_DIR / "bypass_dataset.json", "r", encoding="utf-8") as f:
            rows = json.load(f)
        reqs = [payload_to_request(r.get("transformed", "")) for r in rows if r.get("transformed")]
        out.append((reqs, 1, "bypass_dataset.json"))
    return out


def evaluate_dataset(model, requests, label, name: str) -> dict:
    correct = 0
    total = len(requests)
    scores = []
    for req in requests:
        pred, score = predict_request(req, model)
        scores.append(round(score, 4))
        if pred == label:
            correct += 1
    acc = correct / total if total else 0
    return {
        "name": name,
        "total": total,
        "correct": correct,
        "accuracy": round(acc, 4),
        "label": "benign" if label == 0 else "attack",
        "scores_min": round(min(scores), 4) if scores else None,
        "scores_max": round(max(scores), 4) if scores else None,
        "scores_avg": round(sum(scores) / len(scores), 4) if scores else None,
    }


def main():
    if not MODEL_PATH.exists():
        print("Run train.py first.", file=sys.stderr)
        sys.exit(1)

    model, _ = load_model()
    report = {"datasets": []}

    for reqs, label, name in load_datasets_separately():
        if not reqs:
            continue
        r = evaluate_dataset(model, reqs, label, name)
        report["datasets"].append(r)
        lbl = "benign" if label == 0 else "attack"
        print(f"{name}: {r['correct']}/{r['total']} correct ({lbl}), acc={r['accuracy']}, score [{r['scores_min']}, {r['scores_max']}]")

    bypass_dataset = DATA_DIR / "bypass_dataset.json"
    if bypass_dataset.exists() and "--update" in sys.argv:
        with open(bypass_dataset, "r", encoding="utf-8") as f:
            rows = json.load(f)
        updated = []
        for row in rows:
            req = payload_to_request(row.get("transformed", ""))
            pred, score = predict_request(req, model)
            updated.append({
                **row,
                "waf_score": round(score, 4),
                "bypass": 1 if pred == 0 else 0,
            })
        with open(OUT_BYPASS_UPDATED, "w", encoding="utf-8") as f:
            json.dump(updated, f, ensure_ascii=False, indent=0)
        bypass_count = sum(r["bypass"] for r in updated)
        print(f"Updated bypass_dataset: {bypass_count}/{len(updated)} bypass -> {OUT_BYPASS_UPDATED}")

    total_benign = sum(r["total"] for r in report["datasets"] if r["label"] == "benign")
    total_attack = sum(r["total"] for r in report["datasets"] if r["label"] == "attack")
    correct_benign = sum(r["correct"] for r in report["datasets"] if r["label"] == "benign")
    correct_attack = sum(r["correct"] for r in report["datasets"] if r["label"] == "attack")
    report["overall"] = {
        "benign": {"total": total_benign, "correct": correct_benign, "accuracy": correct_benign / total_benign if total_benign else 0},
        "attack": {"total": total_attack, "correct": correct_attack, "accuracy": correct_attack / total_attack if total_attack else 0},
    }

    with open(OUT_REPORT, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print(f"Report saved to {OUT_REPORT}")


if __name__ == "__main__":
    main()
