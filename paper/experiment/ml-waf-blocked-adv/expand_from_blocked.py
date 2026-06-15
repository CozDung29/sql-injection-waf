import argparse
import json
import sys
from pathlib import Path

from mutate import load_mutate_rules, mutate_from_blocked

DATA_DIR = Path(__file__).resolve().parent / "data"


def default_ml_waf() -> Path:
    return Path(__file__).resolve().parent.parent / "ml-waf"


def load_blocked_lines(path: Path, tail: int | None) -> list[dict]:
    lines = path.read_text(encoding="utf-8").splitlines()
    if tail is not None and tail > 0:
        lines = lines[-tail:]
    rows = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            o = json.loads(line)
            if o.get("payload"):
                rows.append(o)
        except json.JSONDecodeError:
            continue
    return rows


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Read blocked_learned.jsonl from ml-waf (read-only), emit adversarial variants under ml-waf-blocked-adv/data/."
    )
    ap.add_argument(
        "--ml-waf-root",
        type=Path,
        default=None,
        help="Path to ml-waf folder (default: sibling ../ml-waf from this package).",
    )
    ap.add_argument(
        "--blocked-jsonl",
        type=Path,
        default=None,
        help="blocked_learned.jsonl (default: <ml-waf-root>/data/blocked_learned.jsonl).",
    )
    ap.add_argument(
        "--out",
        type=Path,
        default=DATA_DIR / "adversarial_from_blocked.jsonl",
        help="Output jsonl (only written here, never under ml-waf).",
    )
    ap.add_argument(
        "--tail",
        type=int,
        default=None,
        metavar="N",
        help="Only use the last N lines of the blocked file (useful while ml-waf is still appending).",
    )
    ap.add_argument(
        "--max-per-source",
        type=int,
        default=64,
        metavar="N",
        help="Cap variants per blocked row (default: 64).",
    )
    ap.add_argument(
        "--rules",
        type=Path,
        default=None,
        help="mutate_rules.json (default: data/mutate_rules.json in this folder).",
    )
    ns = ap.parse_args(argv)
    ml_waf = ns.ml_waf_root or default_ml_waf()
    blocked = ns.blocked_jsonl or (ml_waf / "data" / "blocked_learned.jsonl")
    if not blocked.is_file():
        print(f"Not found: {blocked}", file=sys.stderr)
        return 1
    if not ml_waf.is_dir():
        print(f"Not found: {ml_waf}", file=sys.stderr)
        return 1

    rows = load_blocked_lines(blocked, ns.tail)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    ns.out.parent.mkdir(parents=True, exist_ok=True)
    rules = load_mutate_rules(ns.rules)

    n_out = 0
    with open(ns.out, "a", encoding="utf-8") as fout:
        for o in rows:
            payload = o["payload"]
            name = o.get("name", "")
            variants = mutate_from_blocked(payload, rules=rules)[: ns.max_per_source]
            for vp, label in variants:
                rec = {
                    "blocked_source_name": name,
                    "blocked_source_payload": payload,
                    "variant_payload": vp,
                    "adv_label": label,
                    "ml_waf_blocked_file": str(blocked.resolve()),
                }
                fout.write(json.dumps(rec, ensure_ascii=False) + "\n")
                n_out += 1

    print(f"Sources: {len(rows)} blocked row(s) -> {n_out} variant line(s) -> {ns.out.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
