import argparse
import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from paper_data_layout import AWS_TEST_DATA, ML_WAF_DATA

from export_tables import (
    write_family_csv,
    write_latex_family_table,
    write_latex_table,
    write_variant_csv,
)
from mutation_analysis import build_full_report, build_paper_summary, write_report
from probe_analysis import full_probe_family_table, full_probe_variant_table


def main() -> None:
    p = argparse.ArgumentParser(description="Mutation / evasion statistics for paper (attack track).")
    p.add_argument(
        "--out",
        type=Path,
        default=Path(__file__).resolve().parent / "exports" / "mutation_report.json",
        help="Main JSON report (compact: top-K transforms + full probe stats)",
    )
    p.add_argument(
        "--out-summary",
        type=Path,
        default=Path(__file__).resolve().parent / "exports" / "paper_summary.json",
        help="Tiny JSON for slides / abstract",
    )
    p.add_argument(
        "--skip-ml-waf",
        action="store_true",
        help="Only use ml-waf-aws-test/data",
    )
    p.add_argument(
        "--skip-aws-test",
        action="store_true",
        help="Only use ml-waf/data",
    )
    p.add_argument("--top-k", type=int, default=120, help="Cap transform histograms per env")
    p.add_argument(
        "--spearman-min",
        type=int,
        default=3,
        help="Min attempts per variant per env for cross-env Spearman",
    )
    p.add_argument(
        "--csv-dir",
        type=Path,
        default=None,
        help="If set, write probe_rates_<env>.csv per environment",
    )
    p.add_argument(
        "--latex",
        type=Path,
        default=None,
        help="If set, write LaTeX table snippet (top variants by bypass rate)",
    )
    p.add_argument(
        "--latex-family",
        type=Path,
        default=None,
        help="If set, write LaTeX table for family-level cohort rates",
    )
    p.add_argument("--latex-max-rows", type=int, default=35)
    p.add_argument(
        "--probe-json-cap",
        type=int,
        default=500,
        help="Max probe variant rows embedded in mutation_report.json (CSV/LaTeX still full)",
    )
    ns = p.parse_args()
    roots: list[tuple[str, Path]] = []
    if not ns.skip_aws_test:
        roots.append(("aws_waf_lab", AWS_TEST_DATA))
    if not ns.skip_ml_waf:
        roots.append(("ml_waf_lab", ML_WAF_DATA))
    if not roots:
        print("no data roots selected", file=sys.stderr)
        sys.exit(1)
    report = build_full_report(
        roots,
        top_k_transforms=ns.top_k,
        spearman_min_attempts=ns.spearman_min,
        probe_json_variant_cap=ns.probe_json_cap,
    )
    write_report(ns.out, report)
    write_report(ns.out_summary, build_paper_summary(report))
    out_extra = {"written": str(ns.out.resolve()), "summary": str(ns.out_summary.resolve())}
    if ns.csv_dir:
        ns.csv_dir.mkdir(parents=True, exist_ok=True)
        for env_key, root in roots:
            probe_f = root / "aws_probe_results.jsonl"
            if not probe_f.is_file():
                continue
            rows = full_probe_variant_table(root)
            write_variant_csv(rows, ns.csv_dir / f"probe_rates_{env_key}.csv", env_key)
            fam = full_probe_family_table(root)
            write_family_csv(fam, ns.csv_dir / f"probe_family_rates_{env_key}.csv", env_key)
        out_extra["csv_dir"] = str(ns.csv_dir.resolve())
    if ns.latex:
        best_env = None
        best_rows: list = []
        for env_key, root in roots:
            probe_f = root / "aws_probe_results.jsonl"
            if not probe_f.is_file():
                continue
            rows = full_probe_variant_table(root)
            if len(rows) > len(best_rows):
                best_rows = rows
                best_env = env_key
        if best_rows and best_env:
            write_latex_table(
                best_rows,
                ns.latex,
                caption=f"Per-variant bypass rate (Wilson 95\\% CI), env={best_env}",
                label="tab:probe-bypass-rates",
                max_rows=ns.latex_max_rows,
            )
            out_extra["latex"] = str(ns.latex.resolve())
    if ns.latex_family:
        best_env = None
        best_fam: list = []
        for env_key, root in roots:
            probe_f = root / "aws_probe_results.jsonl"
            if not probe_f.is_file():
                continue
            fam = full_probe_family_table(root)
            if len(fam) > len(best_fam):
                best_fam = fam
                best_env = env_key
        if best_fam and best_env:
            write_latex_family_table(
                best_fam,
                ns.latex_family,
                caption=f"Cohort-level bypass rate by heuristic family ($v$=distinct variants), env={best_env}",
                label="tab:probe-family-rates",
                max_rows=min(30, ns.latex_max_rows),
            )
            out_extra["latex_family"] = str(ns.latex_family.resolve())
    print(json.dumps(out_extra))


if __name__ == "__main__":
    main()
