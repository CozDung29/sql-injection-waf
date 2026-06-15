import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from evasion.transformers import all_transforms

DATASET_PATH = Path(__file__).resolve().parent.parent / "data" / "bypass_dataset.json"


def main():
    if len(sys.argv) < 2:
        print("Usage: python evasion/suggest_transform.py <raw_sqli_payload>")
        sys.exit(1)
    payload = " ".join(sys.argv[1:])
    if not DATASET_PATH.exists():
        print("Run build_bypass_dataset.py first to get bypass rates.")
        rates = {name: 0.0 for _, name in all_transforms(payload)}
    else:
        with open(DATASET_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        by_t = {}
        for r in data:
            t = r["transform"]
            by_t.setdefault(t, {"bypass": 0, "total": 0})
            by_t[t]["total"] += 1
            if r["bypass"]:
                by_t[t]["bypass"] += 1
        rates = {t: by_t[t]["bypass"] / max(by_t[t]["total"], 1) for t in by_t}
    variants = all_transforms(payload)
    scored = [(transformed, name, rates.get(name, 0.0)) for transformed, name in variants]
    scored.sort(key=lambda x: -x[2])
    print("Suggested transforms (by bypass rate) and example output:")
    for transformed, name, rate in scored[:10]:
        ex = transformed[:70] + "..." if len(transformed) > 70 else transformed
        print(f"  [{name}] (rate={rate:.0%}) -> {ex}")


if __name__ == "__main__":
    main()
