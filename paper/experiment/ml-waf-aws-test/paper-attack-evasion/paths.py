from pathlib import Path

import sys

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from paper_data_layout import (
    AWS_TEST_DATA,
    ML_WAF_DATA,
    ML_WAF_ROOT,
    aws_test_data,
    both_data_roots,
    ml_waf_data,
)

PAPER_DIR = Path(__file__).resolve().parent
