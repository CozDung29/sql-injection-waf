from pathlib import Path
from typing import Any

ML_WAF_AWS_TEST_ROOT = Path(__file__).resolve().parent
ML_WAF_ROOT = ML_WAF_AWS_TEST_ROOT.parent / "ml-waf"
AWS_TEST_DATA = ML_WAF_AWS_TEST_ROOT / "data"
ML_WAF_DATA = ML_WAF_ROOT / "data"


def aws_test_data() -> Path:
    return AWS_TEST_DATA


def ml_waf_data() -> Path:
    return ML_WAF_DATA


def both_data_roots() -> tuple[Path, Path]:
    return AWS_TEST_DATA, ML_WAF_DATA


def data_root_profile(root: Path) -> dict[str, Any]:
    p = Path(root)
    keys = [
        "aws_probe_results.jsonl",
        "bypass_learned.jsonl",
        "blocked_learned.jsonl",
        "adversarial_report.jsonl",
        "attack.json",
        "benign.json",
    ]
    return {
        "directory": str(p.resolve()),
        "present": {k: (p / k).is_file() for k in keys},
    }
