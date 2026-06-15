import subprocess
import sys
from pathlib import Path


def main() -> int:
    ml_waf = Path(__file__).resolve().parent.parent / "ml-waf"
    train_py = ml_waf / "train.py"
    if not train_py.exists():
        print(f"Not found: {train_py}", file=sys.stderr)
        return 1
    subprocess.check_call([sys.executable, str(train_py)], cwd=str(ml_waf))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
