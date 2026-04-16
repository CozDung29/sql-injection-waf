import json
import sys
from pathlib import Path

DATASET_PATH = Path(__file__).resolve().parent.parent / "data" / "bypass_dataset.json"


def main():
    if not DATASET_PATH.exists():
        print("Run: python evasion/build_bypass_dataset.py")
        sys.exit(1)
    with open(DATASET_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    by_transform = {}
    for r in data:
        t = r["transform"]
        by_transform.setdefault(t, {"bypass": 0, "total": 0, "examples": []})
        by_transform[t]["total"] += 1
        if r["bypass"] == 1:
            by_transform[t]["bypass"] += 1
            if len(by_transform[t]["examples"]) < 3:
                by_transform[t]["examples"].append(r["transformed"][:80])
    rows = [(t, by_transform[t]["bypass"], by_transform[t]["total"]) for t in by_transform]
    rows.sort(key=lambda x: (x[1] / max(x[2], 1), x[1]), reverse=True)
    print("Transform | Bypass | Total | Rate")
    print("-" * 45)
    for t, b, tot in rows:
        rate = b / tot if tot else 0
        print(f"  {t:24} | {b:4}   | {tot:4}  | {rate:.2%}")
    print("\nExample payloads that bypassed (first 3 per transform):")
    for t in [r[0] for r in rows if r[1] > 0]:
        ex = by_transform[t]["examples"]
        if ex:
            print(f"  [{t}]")
            for e in ex:
                print(f"    {e}")


if __name__ == "__main__":
    main()
