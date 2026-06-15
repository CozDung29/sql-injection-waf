from __future__ import annotations

import argparse
import json
import sys
import time
from collections import defaultdict
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent / "data"
DEFAULT_IN = DATA_DIR / "test_results.jsonl"
DEFAULT_OUT = DATA_DIR / "adv_learned_encodings.json"


def aggregate_from_test_results(path: Path) -> dict:
    by_label: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    lines_n = 0
    if not path.is_file():
        return {
            "updated_ts": time.time(),
            "source": str(path),
            "test_results_lines": 0,
            "transforms": {},
            "rates": {},
            "totals": {},
        }
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        lines_n += 1
        try:
            o = json.loads(line)
        except json.JSONDecodeError:
            continue
        lab = o.get("adv_label") or "unknown"
        res = o.get("result") or ""
        by_label[lab][res] += 1

    totals: dict[str, int] = defaultdict(int)
    for st in by_label.values():
        for res, c in st.items():
            totals[res] += c

    transforms_out: dict[str, dict[str, int]] = {}
    rates: dict[str, dict[str, float | int | None]] = {}
    for lab, st in by_label.items():
        b = st.get("bypass", 0)
        bl = st.get("blocked", 0)
        u = st.get("unauthorized", 0)
        err = st.get("error", 0)
        transforms_out[lab] = {"bypass": b, "block": bl}
        if u:
            transforms_out[lab]["unauthorized"] = u
        if err:
            transforms_out[lab]["error"] = err
        n = b + bl
        rates[lab] = {
            "bypass_rate": (b / n) if n else None,
            "n_bypass_block": n,
        }

    return {
        "updated_ts": time.time(),
        "source": str(path.resolve()),
        "test_results_lines": lines_n,
        "transforms": transforms_out,
        "rates": rates,
        "totals": dict(totals),
        "note": "Keys are adv_label from mutate_rules. block counts result=blocked (not WAF 403).",
    }


def write_summary(in_path: Path | None = None, out_path: Path | None = None) -> tuple[Path, dict]:
    p_in = in_path or DEFAULT_IN
    p_out = out_path or DEFAULT_OUT
    agg = aggregate_from_test_results(p_in)
    p_out.parent.mkdir(parents=True, exist_ok=True)
    with open(p_out, "w", encoding="utf-8") as f:
        json.dump(agg, f, ensure_ascii=False, indent=2)
    return p_out, agg


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Summarize test_results.jsonl into adv_learned_encodings.json (like ml-waf learned_encodings).",
    )
    ap.add_argument("--in", dest="in_path", type=Path, default=DEFAULT_IN)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ns = ap.parse_args(argv)

    p_out, agg = write_summary(ns.in_path, ns.out)
    print(f"Wrote {p_out.resolve()} ({len(agg['transforms'])} labels)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
