from __future__ import annotations

import json
import statistics
from collections import Counter
from pathlib import Path
from typing import Any

import sys

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from paper_jsonl import load_jsonl

from paper_data_layout import data_root_profile

from probe_analysis import (
    build_probe_report,
    compare_family_probe_envs,
    compare_probe_envs,
)


def _len_stats(payloads: list[str]) -> dict[str, float | int]:
    if not payloads:
        return {"n": 0, "mean": 0.0, "median": 0.0, "min": 0, "max": 0}
    lens = [len(p) for p in payloads]
    return {
        "n": len(lens),
        "mean": float(statistics.mean(lens)),
        "median": float(statistics.median(lens)),
        "min": min(lens),
        "max": max(lens),
    }


def _records_bypass_blocked(
    data_root: Path,
) -> tuple[list[dict], list[dict]]:
    bypass = load_jsonl(data_root / "bypass_learned.jsonl")
    blocked = load_jsonl(data_root / "blocked_learned.jsonl")
    adv = load_jsonl(data_root / "adversarial_report.jsonl")
    for o in adv:
        if o.get("f5") == "bypass":
            bypass.append(o)
        elif o.get("f5") == "block":
            blocked.append(o)
    return _dedup_event_records(bypass), _dedup_event_records(blocked)


def _dedup_event_records(recs: list[dict]) -> list[dict]:
    seen: set[tuple[str, str]] = set()
    out: list[dict] = []
    for r in recs:
        p = r.get("payload")
        if not isinstance(p, str) or not p.strip():
            continue
        nm = str(r.get("name") or "unknown")
        k = (p.strip(), nm)
        if k in seen:
            continue
        seen.add(k)
        out.append(r)
    return out


def _payload_name(rec: dict) -> tuple[str | None, str | None]:
    p = rec.get("payload")
    name = rec.get("name")
    if not isinstance(p, str) or not p.strip():
        return None, None
    return p.strip(), str(name) if name is not None else "unknown"


def analyze_env(data_root: Path, env_key: str) -> dict[str, Any]:
    bypass_recs, blocked_recs = _records_bypass_blocked(data_root)
    bypass_names: Counter[str] = Counter()
    blocked_names: Counter[str] = Counter()
    gen_bypass: list[int] = []
    gen_blocked: list[int] = []

    bypass_payloads: list[str] = []
    for r in bypass_recs:
        pl, nm = _payload_name(r)
        if pl is None:
            continue
        bypass_payloads.append(pl)
        bypass_names[nm or "unknown"] += 1
        g = r.get("gen")
        if isinstance(g, int):
            gen_bypass.append(g)

    blocked_payloads: list[str] = []
    for r in blocked_recs:
        pl, nm = _payload_name(r)
        if pl is None:
            continue
        blocked_payloads.append(pl)
        blocked_names[nm or "unknown"] += 1
        g = r.get("gen")
        if isinstance(g, int):
            gen_blocked.append(g)

    seen_b = set(bypass_payloads)
    seen_k = set(blocked_payloads)
    return {
        "env": env_key,
        "data_root": str(data_root.resolve()),
        "bypass_records": len(bypass_recs),
        "blocked_records": len(blocked_recs),
        "unique_bypass_payloads": len(seen_b),
        "unique_blocked_payloads": len(seen_k),
        "overlap_payloads_bypass_vs_blocked": len(seen_b & seen_k),
        "bypass_by_transform_name": dict(bypass_names.most_common()),
        "blocked_by_transform_name": dict(blocked_names.most_common()),
        "bypass_payload_length": _len_stats(bypass_payloads),
        "blocked_payload_length": _len_stats(blocked_payloads),
        "gen_bypass_stats": (
            {
                "n": len(gen_bypass),
                "mean": float(statistics.mean(gen_bypass)),
                "median": float(statistics.median(gen_bypass)),
                "min": min(gen_bypass),
                "max": max(gen_bypass),
            }
            if gen_bypass
            else {"n": 0}
        ),
        "gen_distribution_bypass": dict(Counter(gen_bypass).most_common()) if gen_bypass else {},
    }


def _top_dict_str_int(d: dict[str, int], k: int) -> dict[str, int]:
    if k <= 0 or len(d) <= k:
        return dict(d)
    items = sorted(d.items(), key=lambda x: (-x[1], x[0]))
    return dict(items[:k])


def merge_counters(env_reports: list[dict[str, Any]]) -> dict[str, Any]:
    mb: Counter[str] = Counter()
    mk: Counter[str] = Counter()
    for er in env_reports:
        for k, v in (er.get("bypass_by_transform_name") or {}).items():
            mb[k] += int(v)
        for k, v in (er.get("blocked_by_transform_name") or {}).items():
            mk[k] += int(v)
    return {
        "merged_bypass_by_transform_name": dict(mb.most_common()),
        "merged_blocked_by_transform_name": dict(mk.most_common()),
        "total_bypass_events": sum(mb.values()),
        "total_blocked_events": sum(mk.values()),
    }


def _slim_env(er: dict[str, Any], top_k: int) -> dict[str, Any]:
    out = {k: v for k, v in er.items() if k not in ("bypass_by_transform_name", "blocked_by_transform_name")}
    bb = er.get("bypass_by_transform_name") or {}
    bk = er.get("blocked_by_transform_name") or {}
    if isinstance(bb, dict):
        out["bypass_by_transform_name_top"] = _top_dict_str_int(
            {str(k): int(v) for k, v in bb.items()}, top_k
        )
    if isinstance(bk, dict):
        out["blocked_by_transform_name_top"] = _top_dict_str_int(
            {str(k): int(v) for k, v in bk.items()}, top_k
        )
    return out


def build_full_report(
    data_roots: list[tuple[str, Path]],
    top_k_transforms: int = 120,
    spearman_min_attempts: int = 3,
    probe_json_variant_cap: int | None = 500,
) -> dict[str, Any]:
    env_reports: list[dict[str, Any]] = []
    probe_reports: list[dict[str, Any]] = []
    for key, root in data_roots:
        if not root.is_dir():
            continue
        env_reports.append(analyze_env(root, key))
        probe_reports.append(
            build_probe_report(root, key, json_variant_row_cap=probe_json_variant_cap)
        )
    merged = merge_counters(env_reports)
    mb = merged.get("merged_bypass_by_transform_name") or {}
    mk = merged.get("merged_blocked_by_transform_name") or {}
    merged_slim = {
        "total_bypass_events": merged.get("total_bypass_events", 0),
        "total_blocked_events": merged.get("total_blocked_events", 0),
        "merged_bypass_top": _top_dict_str_int(
            {str(k): int(v) for k, v in mb.items()}, top_k_transforms
        ),
        "merged_blocked_top": _top_dict_str_int(
            {str(k): int(v) for k, v in mk.items()}, top_k_transforms
        ),
    }
    cross = compare_probe_envs(probe_reports, min_attempts=spearman_min_attempts)
    cross_fam = compare_family_probe_envs(
        probe_reports, min_attempts=max(10, spearman_min_attempts * 2)
    )
    env_slim = {er["env"]: _slim_env(er, top_k_transforms) for er in env_reports}
    return {
        "environments": env_slim,
        "merged_transform_counts": merged_slim,
        "probe_by_environment": {pr["env"]: pr for pr in probe_reports},
        "probe_cross_environment": cross,
        "probe_cross_environment_families": cross_fam,
        "methodology": {
            "attack_track": "mutation_analysis",
            "sources_learned": "bypass_learned.jsonl, blocked_learned.jsonl, adversarial_report.jsonl",
            "sources_probe": "aws_probe_results.jsonl (per-variant attempts, Wilson 95% CI on bypass rate)",
            "family_aggregation": "Heuristic cohorts in variant_families.py (+ variant_family_rules.json): larger n per row than single-variant rates; suited for rule-based WAF reporting.",
            "generalization": "multiple data roots; Spearman variant- and family-level where both envs have probe logs",
        },
    }


def build_paper_summary(full: dict[str, Any]) -> dict[str, Any]:
    probe = full.get("probe_by_environment") or {}
    envs = full.get("environments") or {}
    overall = {}
    for env, pr in probe.items():
        if pr.get("has_probe"):
            o = dict(pr.get("overall") or {})
            o["probe_http_available"] = True
            overall[env] = o
        else:
            e = envs.get(env) or {}
            overall[env] = {
                "probe_http_available": False,
                "why": "No aws_probe_results.jsonl in this data directory; no HTTP probe aggregate (attempts / bypass rate) for this env.",
                "from_learned_logs": {
                    "bypass_events": e.get("bypass_records"),
                    "blocked_events": e.get("blocked_records"),
                    "unique_bypass_payloads": e.get("unique_bypass_payloads"),
                    "unique_blocked_payloads": e.get("unique_blocked_payloads"),
                    "overlap_bypass_vs_blocked_payloads": e.get(
                        "overlap_payloads_bypass_vs_blocked"
                    ),
                },
                "to_enable_probe_block": "Add aws_probe_results.jsonl under this env data/ (same schema as ml-waf-aws-test) or point run_probe output here.",
            }
    fam_preview: dict[str, Any] = {}
    for env, pr in probe.items():
        if not pr.get("has_probe"):
            continue
        rows = (pr.get("family_aggregation") or {}).get("family_rows") or []
        fam_preview[env] = rows[:15]
    data_avail: dict[str, Any] = {}
    for env, e in (full.get("environments") or {}).items():
        dr = e.get("data_root")
        if isinstance(dr, str) and dr.strip():
            data_avail[env] = data_root_profile(Path(dr))
    return {
        "how_to_read_two_roots": {
            "aws_waf_lab": "Data under ml-waf-aws-test/data — AWS HTTP probe (aws_probe_results.jsonl) and learned logs for that lab run.",
            "ml_waf_lab": "Data under ml-waf/data — separate lab (ModSecurity / local runs). Has bypass_learned etc.; usually no aws_probe_results.jsonl unless you copy or probe there.",
            "cross_env_metrics": "Spearman needs aws_probe_results.jsonl in both directories; otherwise null is expected.",
        },
        "data_availability_by_env": data_avail,
        "probe_overall_bypass_rate_by_env": overall,
        "cross_environment_variants": full.get("probe_cross_environment"),
        "cross_environment_families": full.get("probe_cross_environment_families"),
        "top_family_cohorts_preview": fam_preview,
        "learned_totals": {
            env: {
                "unique_bypass_payloads": e.get("unique_bypass_payloads"),
                "unique_blocked_payloads": e.get("unique_blocked_payloads"),
            }
            for env, e in (full.get("environments") or {}).items()
        },
    }


def write_report(out_path: Path, report: dict[str, Any]) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
