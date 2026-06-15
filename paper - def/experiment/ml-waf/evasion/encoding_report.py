import argparse
import csv
import json
import time
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
METRICS_DIR = DATA_DIR / "metrics"
LEARNED_FILE = DATA_DIR / "learned_encodings.json"
DEFAULT_REFERENCE = DATA_DIR / "learned_encodings.reference.json"


def load_json(path: Path) -> dict:
    if not path.exists():
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def totals(transforms: dict) -> tuple[int, int]:
    b = bl = 0
    for v in transforms.values():
        b += int(v.get("bypass", 0))
        bl += int(v.get("block", 0))
    return b, bl


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--reference",
        type=Path,
        default=DEFAULT_REFERENCE,
        help="Baseline JSON (default: data/learned_encodings.reference.json)",
    )
    ap.add_argument("--current", type=Path, default=LEARNED_FILE, help="Current learned_encodings.json")
    ns = ap.parse_args()

    cur = load_json(ns.current)
    ref = load_json(ns.reference)
    cur_t = cur.get("transforms") or {}
    ref_t = ref.get("transforms") or {}

    METRICS_DIR.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")

    csv_path = METRICS_DIR / f"encoding_summary_{ts}.csv"
    keys = sorted(set(cur_t.keys()) | set(ref_t.keys()))
    with open(csv_path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["key", "bypass", "block", "total", "rate"])
        for k in keys:
            v = cur_t.get(k, {"bypass": 0, "block": 0})
            b, bl = int(v.get("bypass", 0)), int(v.get("block", 0))
            tot = b + bl
            rate = (b / tot) if tot else 0.0
            w.writerow([k, b, bl, tot, f"{rate:.4f}"])

    latest_csv = METRICS_DIR / "encoding_summary_latest.csv"
    latest_csv.write_text(csv_path.read_text(encoding="utf-8"), encoding="utf-8")

    cb, cbl = totals(cur_t)
    rb, rbl = totals(ref_t)
    diff_obj = {
        "ts": time.time(),
        "current_file": str(ns.current),
        "reference_file": str(ns.reference) if ref_t else None,
        "current_totals": {"bypass": cb, "block": cbl, "all": cb + cbl},
        "reference_totals": {"bypass": rb, "block": rbl, "all": rb + rbl},
        "per_key": [],
    }

    lines = []
    lines.append(f"current:  bypass={cb} block={cbl} total={cb + cbl}")
    if ref_t:
        lines.append(f"reference: bypass={rb} block={rbl} total={rb + rbl}")
        lines.append(f"delta:    bypass={cb - rb} block={cbl - rbl} total={(cb + cbl) - (rb + rbl)}")
    lines.append("")
    lines.append(f"{'key':<22} {'ref_b':>8} {'ref_bl':>8} {'cur_b':>8} {'cur_bl':>8} {'d_tot':>8}")
    lines.append("-" * 70)

    for k in keys:
        rv = ref_t.get(k, {"bypass": 0, "block": 0})
        cv = cur_t.get(k, {"bypass": 0, "block": 0})
        rb_, rbl_ = int(rv.get("bypass", 0)), int(rv.get("block", 0))
        cb_, cbl_ = int(cv.get("bypass", 0)), int(cv.get("block", 0))
        d = (cb_ + cbl_) - (rb_ + rbl_)
        diff_obj["per_key"].append(
            {
                "key": k,
                "ref_bypass": rb_,
                "ref_block": rbl_,
                "cur_bypass": cb_,
                "cur_block": cbl_,
                "delta_total": d,
            }
        )
        if ref_t:
            lines.append(f"{k:<22} {rb_:>8} {rbl_:>8} {cb_:>8} {cbl_:>8} {d:>8}")

    json_path = METRICS_DIR / f"encoding_vs_reference_{ts}.json"
    txt_path = METRICS_DIR / f"encoding_vs_reference_{ts}.txt"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(diff_obj, f, ensure_ascii=False, indent=2)
    txt_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    latest_json = METRICS_DIR / "encoding_vs_reference_latest.json"
    latest_txt = METRICS_DIR / "encoding_vs_reference_latest.txt"
    latest_json.write_text(json_path.read_text(encoding="utf-8"), encoding="utf-8")
    latest_txt.write_text(txt_path.read_text(encoding="utf-8"), encoding="utf-8")

    print("\n".join(lines))
    print(f"\nWrote: {csv_path}")
    print(f"       {latest_csv} (copy)")
    print(f"       {json_path}")
    print(f"       {txt_path}")
    print(f"       {latest_json} / {latest_txt} (latest)")


if __name__ == "__main__":
    main()
