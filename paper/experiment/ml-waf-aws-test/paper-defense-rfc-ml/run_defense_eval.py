import argparse
import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from paper_data_layout import AWS_TEST_DATA, ML_WAF_DATA

from ml_baseline import defense_comparison_report, write_json


def main() -> None:
    p = argparse.ArgumentParser(description="RFC canonicalization + ML baseline (defense track).")
    p.add_argument(
        "--data-dir",
        type=Path,
        default=None,
        help="Directory with attack.json and benign.json (default: ml-waf/data)",
    )
    p.add_argument(
        "--compare-aws-test",
        action="store_true",
        help="Also run on ml-waf-aws-test/data if attack.json/benign.json exist",
    )
    p.add_argument(
        "--out",
        type=Path,
        default=Path(__file__).resolve().parent / "exports" / "defense_eval.json",
    )
    p.add_argument("--seed", type=int, default=42)
    ns = p.parse_args()
    reports: dict = {}
    primary = ns.data_dir or ML_WAF_DATA
    reports["primary_ml_waf_data"] = defense_comparison_report(primary, seed=ns.seed)
    if ns.compare_aws_test and AWS_TEST_DATA.is_dir():
        ap = AWS_TEST_DATA / "attack.json"
        bp = AWS_TEST_DATA / "benign.json"
        if ap.is_file() and bp.is_file():
            reports["secondary_aws_test_data"] = defense_comparison_report(AWS_TEST_DATA, seed=ns.seed)
        else:
            reports["secondary_aws_test_data"] = {
                "skipped": True,
                "reason": "add attack.json and benign.json under ml-waf-aws-test/data to compare environments",
            }
    write_json(ns.out, reports)
    print(json.dumps({"written": str(ns.out.resolve()), "keys": list(reports.keys())}))


if __name__ == "__main__":
    main()
