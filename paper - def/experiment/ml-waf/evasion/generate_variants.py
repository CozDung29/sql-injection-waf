import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from evasion.transformers import all_transforms

PAYLOADS_PATH = Path(__file__).resolve().parent.parent / "data" / "payloads" / "base_sqli.json"
OUT_PATH = Path(__file__).resolve().parent.parent / "data" / "payloads" / "variants.json"


def main():
    with open(PAYLOADS_PATH, "r", encoding="utf-8") as f:
        base_list = json.load(f)
    out = []
    seen = set()
    for base in base_list:
        for transformed, name in all_transforms(base):
            key = (transformed[:200], name)
            if key in seen:
                continue
            seen.add(key)
            out.append({"base": base, "transformed": transformed, "transform": name})
    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=0)
    print(f"Generated {len(out)} variants from {len(base_list)} base payloads -> {OUT_PATH}")


if __name__ == "__main__":
    main()
