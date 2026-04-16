import argparse
import json
import sys
from pathlib import Path

from payload_io import load_all
from modsecurity_eval import modsec_blocks
from ml_surrogate_eval import MlSurrogate


def _rate(total: int, blocked: int) -> float:
    if total == 0:
        return 0.0
    return (total - blocked) / total


def _metric(total: int, blocked: int) -> dict:
    return {
        "n_blocked": blocked,
        "n_bypass": total - blocked,
        "bypass_rate": _rate(total, blocked),
    }


def main(argv: list[str] | None = None) -> int:
    here = Path(__file__).resolve().parent
    default_ds = [
        here.parent / "ml-waf" / "data" / "blocked_learned.jsonl",
        here.parent / "ml-waf-experiment" / "data" / "blocked_learned.jsonl",
    ]
    ap = argparse.ArgumentParser(
        description="Evaluate attack payloads against ModSecurity-style regex and ml-waf RF surrogate; report bypass rates per system."
    )
    ap.add_argument(
        "inputs",
        nargs="*",
        type=Path,
        help="JSONL or JSON files (default: ml-waf blocked_learned.jsonl if present)",
    )
    ap.add_argument("--param", default="id", help="Query parameter name for synthetic request")
    ap.add_argument("--ml-model", type=Path, default=None, help="Path to waf_model.joblib")
    ap.add_argument("--skip-ml", action="store_true", help="Do not load or score ML surrogate")
    ap.add_argument("--skip-modsec", action="store_true", help="Skip ModSecurity regex layer")
    ap.add_argument("--by-group", action="store_true", help="Break down metrics by adv_label/transform/name")
    ap.add_argument("--out", type=Path, default=None, help="Write JSON report to this path")
    ap.add_argument("--limit", type=int, default=None, help="Max payloads to evaluate")
    ns = ap.parse_args(argv)

    if ns.skip_ml and ns.skip_modsec:
        print("Cannot use both --skip-ml and --skip-modsec.", file=sys.stderr)
        return 1

    paths = list(ns.inputs) if ns.inputs else []
    if not paths:
        paths = [p for p in default_ds if p.exists()]
    if not paths:
        print("No input files. Pass JSONL/JSON paths or add ml-waf/data/blocked_learned.jsonl", file=sys.stderr)
        return 1

    rows = load_all(paths)
    if ns.limit is not None:
        rows = rows[: ns.limit]

    ml = None
    use_ml = not ns.skip_ml
    use_mod = not ns.skip_modsec
    if use_ml:
        ml = MlSurrogate(ns.ml_model)
        try:
            ml.load()
        except FileNotFoundError as e:
            print(str(e), file=sys.stderr)
            print("Use --skip-ml or train ml-waf (cd ml-waf && python3 train.py)", file=sys.stderr)
            return 1

    total = 0
    bm = 0
    bml = 0
    bor = 0
    band = 0

    by_group: dict[str, dict[str, int]] = {}

    def group_key(g: str | None) -> str:
        return g if g else "_ungrouped"

    for payload, g in rows:
        total += 1
        mod_b = modsec_blocks(payload, ns.param) if use_mod else False
        ml_b = ml.blocks(payload, ns.param) if ml is not None else False
        if mod_b:
            bm += 1
        if ml_b:
            bml += 1
        if mod_b or ml_b:
            bor += 1
        if mod_b and ml_b:
            band += 1

        if ns.by_group:
            key = group_key(g)
            d = by_group.setdefault(key, {"total": 0, "mod": 0, "ml": 0, "or": 0, "and": 0})
            d["total"] += 1
            if mod_b:
                d["mod"] += 1
            if ml_b:
                d["ml"] += 1
            if mod_b or ml_b:
                d["or"] += 1
            if mod_b and ml_b:
                d["and"] += 1

    summary: dict = {"n_total": total}
    if use_mod:
        summary["modsecurity_regex"] = _metric(total, bm)
    if use_ml:
        summary["ml_rf_surrogate"] = _metric(total, bml)
    if use_mod and use_ml:
        summary["combined_or_block_if_either"] = _metric(total, bor)
        summary["combined_and_block_if_both"] = _metric(total, band)

    report: dict = {
        "inputs": [str(p.resolve()) for p in paths],
        "param": ns.param,
        "summary": summary,
    }

    if ns.by_group and by_group:
        groups_out: dict[str, dict] = {}
        for k, d in sorted(by_group.items()):
            t = d["total"]
            entry: dict = {"n_total": t}
            if use_mod:
                entry["modsecurity_regex"] = _metric(t, d["mod"])
            if use_ml:
                entry["ml_rf_surrogate"] = _metric(t, d["ml"])
            if use_mod and use_ml:
                entry["combined_or"] = _metric(t, d["or"])
                entry["combined_and"] = _metric(t, d["and"])
            groups_out[k] = entry
        report["by_group"] = groups_out

    text = json.dumps(report, indent=2, ensure_ascii=False)
    print(text)
    if ns.out:
        ns.out.parent.mkdir(parents=True, exist_ok=True)
        ns.out.write_text(text, encoding="utf-8")
        print(f"Wrote {ns.out.resolve()}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
