import argparse
import json
import shutil
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from evasion.stats_utils import wilson_upper_bound

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
METRICS_DIR = DATA_DIR / "metrics" / "runs"
LEARNED_FILE = DATA_DIR / "learned_encodings.json"
POLICY_FILE = DATA_DIR / "transform_policy.json"

DEFAULT_NEVER_EXCLUDE = ("other", "identity")
DEFAULT_MIN_SAMPLES = 30
DEFAULT_EXPLORE_RATE = 0.08


def load_learned() -> dict:
    if not LEARNED_FILE.exists():
        return {}
    try:
        with open(LEARNED_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def snapshot() -> Path | None:
    data = load_learned()
    if not data.get("transforms"):
        return None
    METRICS_DIR.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")
    dest = METRICS_DIR / f"learned_encodings_{ts}.json"
    shutil.copy2(LEARNED_FILE, dest)
    return dest


def stats_rows(transforms: dict) -> list[dict]:
    rows = []
    for key, v in transforms.items():
        b = int(v.get("bypass", 0))
        bl = int(v.get("block", 0))
        total = b + bl
        rate = (b / total) if total else 0.0
        rows.append(
            {
                "key": key,
                "bypass": b,
                "block": bl,
                "total": total,
                "rate": round(rate, 4),
            }
        )
    rows.sort(key=lambda r: (r["rate"], r["total"]), reverse=True)
    return rows


def build_policy(
    transforms: dict,
    min_samples: int = DEFAULT_MIN_SAMPLES,
    explore_rate: float = DEFAULT_EXPLORE_RATE,
    never_exclude: tuple[str, ...] = DEFAULT_NEVER_EXCLUDE,
    use_wilson: bool = False,
    wilson_z: float = 1.96,
    wilson_ub_max: float = 0.08,
    explore_mode: str = "fixed",
) -> dict:
    exclude = []
    for key, v in transforms.items():
        b = int(v.get("bypass", 0))
        bl = int(v.get("block", 0))
        total = b + bl
        if key in never_exclude:
            continue
        if total < min_samples:
            continue
        if use_wilson:
            if b > 0:
                continue
            wub = wilson_upper_bound(b, total, z=wilson_z)
            if wub < wilson_ub_max:
                exclude.append(key)
        else:
            if b == 0:
                exclude.append(key)
    exclude = sorted(set(exclude))
    return {
        "enabled": True,
        "min_samples_for_exclude": min_samples,
        "explore_rate": explore_rate,
        "never_exclude": list(never_exclude),
        "exclude": exclude,
        "exclude_rule": "wilson" if use_wilson else "zero_bypass",
        "wilson_z": wilson_z,
        "wilson_ub_max": wilson_ub_max,
        "explore_mode": explore_mode,
        "built_ts": time.time(),
    }


def write_summary(rows: list[dict], path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"rows": rows, "ts": time.time()}, f, ensure_ascii=False, indent=2)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--min-samples", type=int, default=DEFAULT_MIN_SAMPLES)
    p.add_argument("--explore-rate", type=float, default=DEFAULT_EXPLORE_RATE)
    p.add_argument("--no-snapshot", action="store_true")
    p.add_argument("--summary", action="store_true")
    p.add_argument(
        "--wilson",
        action="store_true",
        help="Exclude only when Wilson upper bound on bypass rate is below --wilson-ub-max (needs --min-samples)",
    )
    p.add_argument("--wilson-z", type=float, default=1.96)
    p.add_argument("--wilson-ub-max", type=float, default=0.08)
    p.add_argument(
        "--explore-thompson",
        action="store_true",
        help="Write policy with explore_mode=thompson (Beta draw for excluded arms)",
    )
    args = p.parse_args()

    data = load_learned()
    transforms = data.get("transforms") or {}
    rows = stats_rows(transforms)

    if not args.no_snapshot and transforms:
        snap = snapshot()
        if snap:
            print(f"Snapshot: {snap}")

    if args.summary:
        summary_path = METRICS_DIR / f"summary_{time.strftime('%Y%m%d_%H%M%S')}.json"
        write_summary(rows, summary_path)
        print(f"Summary: {summary_path}")

    policy = build_policy(
        transforms,
        min_samples=args.min_samples,
        explore_rate=args.explore_rate,
        use_wilson=args.wilson,
        wilson_z=args.wilson_z,
        wilson_ub_max=args.wilson_ub_max,
        explore_mode="thompson" if args.explore_thompson else "fixed",
    )
    with open(POLICY_FILE, "w", encoding="utf-8") as f:
        json.dump(policy, f, ensure_ascii=False, indent=2)
    print(f"Policy: {POLICY_FILE}")
    print(f"  exclude ({len(policy['exclude'])}): {policy['exclude']}")
    for r in rows[:12]:
        print(f"  {r['key']}: rate={r['rate']} n={r['total']}")


if __name__ == "__main__":
    main()
