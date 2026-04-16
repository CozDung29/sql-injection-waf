import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from predict import predict_request, load_model

VARIANTS_PATH = Path(__file__).resolve().parent.parent / "data" / "payloads" / "variants.json"
MODEL_PATH = Path(__file__).resolve().parent.parent / "models" / "waf_model.joblib"
OUT_PATH = Path(__file__).resolve().parent.parent / "data" / "bypass_dataset.json"


def request_from_payload(payload: str, in_query: bool = True) -> dict:
    if in_query:
        return {"method": "GET", "path": "/api", "query": f"id={payload}", "headers": {}, "body": ""}
    return {"method": "POST", "path": "/api", "query": "", "headers": {"content-type": "application/json"}, "body": json.dumps({"id": payload})}


def main():
    if not MODEL_PATH.exists():
        print("Run train.py first.", file=sys.stderr)
        sys.exit(1)
    if not VARIANTS_PATH.exists():
        print("Run: python evasion/generate_variants.py", file=sys.stderr)
        sys.exit(1)
    with open(VARIANTS_PATH, "r", encoding="utf-8") as f:
        variants = json.load(f)
    model, _ = load_model()
    results = []
    for i, row in enumerate(variants):
        req = request_from_payload(row["transformed"], in_query=True)
        pred, score = predict_request(req, model)
        bypass = 1 if pred == 0 else 0
        results.append({
            "base": row["base"],
            "transformed": row["transformed"][:500],
            "transform": row["transform"],
            "waf_score": round(score, 4),
            "bypass": bypass,
        })
        if (i + 1) % 50 == 0:
            print(f"  {i+1}/{len(variants)}")
    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=0)
    bypass_count = sum(r["bypass"] for r in results)
    by_transform = {}
    for r in results:
        t = r["transform"]
        by_transform.setdefault(t, {"total": 0, "bypass": 0})
        by_transform[t]["total"] += 1
        if r["bypass"]:
            by_transform[t]["bypass"] += 1
    print(f"Bypass: {bypass_count}/{len(results)} -> {OUT_PATH}")
    print("By transform (bypass/total):")
    for t in sorted(by_transform.keys()):
        b, tot = by_transform[t]["bypass"], by_transform[t]["total"]
        print(f"  {t}: {b}/{tot}")


if __name__ == "__main__":
    main()
