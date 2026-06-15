import sys
from pathlib import Path


def ml_waf_root() -> Path:
    return Path(__file__).resolve().parent.parent / "ml-waf"


def ensure_ml_waf_imports() -> Path:
    root = ml_waf_root()
    s = str(root)
    if s not in sys.path:
        sys.path.insert(0, s)
    return root
