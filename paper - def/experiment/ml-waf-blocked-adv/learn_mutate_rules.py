import argparse
import json
import shutil
import sys
from collections import defaultdict
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent / "data"


def load_stats(path: Path) -> dict[str, dict[str, int]]:
    by_label: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            o = json.loads(line)
        except json.JSONDecodeError:
            continue
        lab = o.get("adv_label")
        if not lab:
            continue
        res = o.get("result") or ""
        by_label[lab][res] += 1
    return {k: dict(v) for k, v in by_label.items()}


def rate(stats: dict[str, int]) -> float:
    b = stats.get("bypass", 0)
    bl = stats.get("blocked", 0)
    t = b + bl
    if t == 0:
        return -1.0
    return b / t


def reorder_steps(steps: list[dict], label_order: list[str]) -> list[dict]:
    by_lab = {s["label"]: s for s in steps}
    out: list[dict] = []
    for lab in label_order:
        if lab in by_lab:
            out.append(by_lab[lab])
    for s in steps:
        if s["label"] not in {x["label"] for x in out}:
            out.append(s)
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Rank adv_label by bypass rate from test_results.jsonl, rewrite mutate_rules order (heuristic)."
    )
    ap.add_argument(
        "--test-results",
        type=Path,
        default=DATA_DIR / "test_results.jsonl",
        help="Output from test_variants.py",
    )
    ap.add_argument(
        "--base-rules",
        type=Path,
        default=DATA_DIR / "mutate_rules.json",
        help="Current mutate_rules.json to reorder",
    )
    ap.add_argument(
        "--out",
        type=Path,
        default=DATA_DIR / "mutate_rules.suggested.json",
        help="Suggested rules file (review before replacing mutate_rules.json)",
    )
    ap.add_argument(
        "--apply",
        action="store_true",
        help="After writing --out, copy it over --base-rules (mutate_rules.json).",
    )
    ns = ap.parse_args(argv)

    if not ns.test_results.is_file():
        print(f"Not found: {ns.test_results}", file=sys.stderr)
        return 1
    if not ns.base_rules.is_file():
        print(f"Not found: {ns.base_rules}", file=sys.stderr)
        return 1

    stats = load_stats(ns.test_results)
    if not stats:
        print("No adv_label stats in test results (empty file or no completed tests). Rule order unchanged.")
    ranked = sorted(stats.keys(), key=lambda lab: (-rate(stats[lab]), -sum(stats[lab].values())))

    with open(ns.base_rules, encoding="utf-8") as f:
        rules = json.load(f)

    rules["transform_steps"] = reorder_steps(rules.get("transform_steps", []), ranked)
    rules["regex_rules"] = reorder_steps(rules.get("regex_rules", []), ranked)

    ns.out.parent.mkdir(parents=True, exist_ok=True)
    with open(ns.out, "w", encoding="utf-8") as f:
        json.dump(rules, f, ensure_ascii=False, indent=2)

    print("adv_label -> bypass / (bypass+blocked), n_total")
    for lab in ranked:
        st = stats[lab]
        b, bl = st.get("bypass", 0), st.get("blocked", 0)
        tot = sum(st.values())
        r = rate(st)
        print(f"  {lab}: rate={r:.3f} bypass={b} blocked={bl} n={tot}")
    print(f"\nWrote {ns.out.resolve()}")
    if ns.apply:
        shutil.copyfile(ns.out, ns.base_rules)
        print(f"Applied -> {ns.base_rules.resolve()}")
    else:
        print("Copy to data/mutate_rules.json after review, or use --apply.")
    from adv_learned_encodings import write_summary

    write_summary(ns.test_results)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
