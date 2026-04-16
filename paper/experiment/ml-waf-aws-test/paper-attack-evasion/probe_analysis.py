from __future__ import annotations

import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from paper_jsonl import iter_jsonl

from stats_core import cross_env_spearman, wilson_ci
from variant_families import variant_family


def aggregate_probe_file(path: Path) -> dict[str, dict[str, int]]:
    agg: dict[str, dict[str, int]] = defaultdict(
        lambda: {"n": 0, "bypass": 0, "blocked": 0, "other": 0}
    )
    if not path.is_file():
        return {}
    for r in iter_jsonl(path):
        v = str(r.get("variant") or r.get("name") or "unknown")
        res = r.get("result")
        agg[v]["n"] += 1
        if res == "bypass":
            agg[v]["bypass"] += 1
        elif res == "blocked":
            agg[v]["blocked"] += 1
        else:
            agg[v]["other"] += 1
    return dict(agg)


def aggregate_by_family(
    agg: dict[str, dict[str, int]],
) -> tuple[dict[str, dict[str, int]], dict[str, int]]:
    out: dict[str, dict[str, int]] = defaultdict(
        lambda: {"n": 0, "bypass": 0, "blocked": 0, "other": 0}
    )
    distinct: dict[str, set[str]] = defaultdict(set)
    for variant, s in agg.items():
        fam = variant_family(variant)
        distinct[fam].add(variant)
        for k in ("n", "bypass", "blocked", "other"):
            out[fam][k] += s[k]
    n_var = {k: len(v) for k, v in distinct.items()}
    return dict(out), n_var


def family_rates_with_ci(
    agg_f: dict[str, dict[str, int]],
    distinct_variants_per_family: dict[str, int],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    total_n = sum(s["n"] for s in agg_f.values())
    total_bypass = sum(s["bypass"] for s in agg_f.values())
    global_rate = total_bypass / total_n if total_n else 0.0
    for family in sorted(agg_f.keys()):
        s = agg_f[family]
        n = s["n"]
        b = s["bypass"]
        rate = b / n if n else 0.0
        lo, hi = wilson_ci(b, n)
        rows.append(
            {
                "family": family,
                "distinct_variants": int(distinct_variants_per_family.get(family, 0)),
                "attempts": n,
                "bypass": b,
                "blocked": s["blocked"],
                "other": s["other"],
                "bypass_rate": rate,
                "bypass_rate_ci95_low": lo,
                "bypass_rate_ci95_high": hi,
                "bypass_rate_minus_global": rate - global_rate,
            }
        )
    rows.sort(key=lambda x: (-x["bypass_rate"], -x["attempts"], x["family"]))
    return rows


def rates_with_ci(agg: dict[str, dict[str, int]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    total_n = sum(s["n"] for s in agg.values())
    total_bypass = sum(s["bypass"] for s in agg.values())
    global_rate = total_bypass / total_n if total_n else 0.0
    for variant in sorted(agg.keys()):
        s = agg[variant]
        n = s["n"]
        b = s["bypass"]
        rate = b / n if n else 0.0
        lo, hi = wilson_ci(b, n)
        rows.append(
            {
                "variant": variant,
                "attempts": n,
                "bypass": b,
                "blocked": s["blocked"],
                "other": s["other"],
                "bypass_rate": rate,
                "bypass_rate_ci95_low": lo,
                "bypass_rate_ci95_high": hi,
                "bypass_rate_minus_global": rate - global_rate,
            }
        )
    rows.sort(key=lambda x: (-x["bypass_rate"], -x["attempts"], x["variant"]))
    return rows


def build_probe_report(
    data_root: Path,
    env_key: str,
    json_variant_row_cap: int | None = 500,
) -> dict[str, Any]:
    probe_path = data_root / "aws_probe_results.jsonl"
    agg = aggregate_probe_file(probe_path)
    if not agg:
        return {
            "env": env_key,
            "probe_file": str(probe_path.resolve()),
            "has_probe": False,
            "variant_rows": [],
            "variant_rows_total": 0,
            "overall": {},
        }
    rows = rates_with_ci(agg)
    agg_f, distinct_v = aggregate_by_family(agg)
    fam_rows = family_rates_with_ci(agg_f, distinct_v)
    total_n = sum(s["n"] for s in agg.values())
    total_bypass = sum(s["bypass"] for s in agg.values())
    rates_map = {r["variant"]: r["bypass_rate"] for r in rows}
    n_map = {r["variant"]: r["attempts"] for r in rows}
    rates_fam = {r["family"]: r["bypass_rate"] for r in fam_rows}
    n_fam = {r["family"]: r["attempts"] for r in fam_rows}
    rows_json = rows
    if json_variant_row_cap is not None and len(rows) > json_variant_row_cap:
        rows_json = rows[: json_variant_row_cap]
    fam_json = fam_rows
    cap_f = min(80, len(fam_rows))
    if len(fam_json) > cap_f:
        fam_json = fam_json[:cap_f]
    return {
        "env": env_key,
        "probe_file": str(probe_path.resolve()),
        "has_probe": True,
        "variant_rows": rows_json,
        "variant_rows_total": len(rows),
        "variant_rows_truncated": len(rows_json) < len(rows),
        "rates_by_variant": rates_map,
        "attempts_by_variant": n_map,
        "family_aggregation": {
            "description": "Variants grouped by heuristic family (rule-based WAF: interpret as cohort-level rates, not i.i.d. trials per variant).",
            "family_rows": fam_json,
            "family_rows_total": len(fam_rows),
            "rates_by_family": rates_fam,
            "attempts_by_family": n_fam,
        },
        "overall": {
            "total_attempts": total_n,
            "total_bypass": total_bypass,
            "overall_bypass_rate": total_bypass / total_n if total_n else 0.0,
        },
    }


def full_probe_variant_table(data_root: Path) -> list[dict[str, Any]]:
    agg = aggregate_probe_file(data_root / "aws_probe_results.jsonl")
    return rates_with_ci(agg)


def full_probe_family_table(data_root: Path) -> list[dict[str, Any]]:
    agg = aggregate_probe_file(data_root / "aws_probe_results.jsonl")
    agg_f, distinct_v = aggregate_by_family(agg)
    return family_rates_with_ci(agg_f, distinct_v)


def compare_probe_envs(
    reports: list[dict[str, Any]],
    min_attempts: int = 3,
) -> dict[str, Any]:
    if len(reports) < 2:
        return {"spearman_across_envs": None, "reason": "need_two_probe_environments"}
    r0, r1 = reports[0], reports[1]
    if not r0.get("has_probe") or not r1.get("has_probe"):
        return {"spearman_across_envs": None, "reason": "missing_probe_file_in_one_env"}
    ra = r0.get("rates_by_variant") or {}
    rb = r1.get("rates_by_variant") or {}
    na = r0.get("attempts_by_variant") or {}
    nb = r1.get("attempts_by_variant") or {}
    sp = cross_env_spearman(ra, rb, na, nb, min_attempts=min_attempts)
    return {
        "env_a": r0.get("env"),
        "env_b": r1.get("env"),
        "min_attempts_per_env": min_attempts,
        "spearman_across_envs": sp,
    }


def compare_family_probe_envs(
    reports: list[dict[str, Any]],
    min_attempts: int = 10,
) -> dict[str, Any]:
    if len(reports) < 2:
        return {"spearman_families": None, "reason": "need_two_probe_environments"}
    r0, r1 = reports[0], reports[1]
    if not r0.get("has_probe") or not r1.get("has_probe"):
        return {"spearman_families": None, "reason": "missing_probe_file_in_one_env"}
    fa = (r0.get("family_aggregation") or {}).get("rates_by_family") or {}
    fb = (r1.get("family_aggregation") or {}).get("rates_by_family") or {}
    na = (r0.get("family_aggregation") or {}).get("attempts_by_family") or {}
    nb = (r1.get("family_aggregation") or {}).get("attempts_by_family") or {}
    sp = cross_env_spearman(fa, fb, na, nb, min_attempts=min_attempts)
    return {
        "env_a": r0.get("env"),
        "env_b": r1.get("env"),
        "min_attempts_per_family_per_env": min_attempts,
        "spearman_families": sp,
    }
