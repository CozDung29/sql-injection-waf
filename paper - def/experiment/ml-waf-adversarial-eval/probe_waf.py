import argparse
import json
import sys
import time
from pathlib import Path
from urllib.parse import quote
from urllib.request import Request, urlopen

from payload_io import load_all


def _unwrap_waf_json(obj: dict) -> dict:
    inner = obj.get("data")
    if isinstance(inner, dict) and ("blocked" in inner or "pred" in inner):
        return inner
    return obj


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Send each payload to the WAF HTTP service (serve_waf.py) and measure bypass rate (attack with blocked=false)."
    )
    ap.add_argument("inputs", nargs="+", type=Path, help="JSON / JSONL dataset")
    ap.add_argument(
        "--base-url",
        default="http://127.0.0.1:8787",
        help="Host + optional path prefix, e.g. http://127.0.0.1:8787 or http://localhost:3001",
    )
    ap.add_argument(
        "--evaluate-path",
        default="/waf",
        help="Path appended to base-url (default /waf for serve_waf.py; use /waf-eval for Nest proxy)",
    )
    ap.add_argument("--out", type=Path, default=None, help="JSONL per-row results")
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--sleep", type=float, default=0.0)
    ap.add_argument("--timeout", type=float, default=30.0)
    ns = ap.parse_args(argv)

    base = ns.base_url.rstrip("/")
    ep = ns.evaluate_path if ns.evaluate_path.startswith("/") else f"/{ns.evaluate_path}"
    rows = load_all(list(ns.inputs))
    if ns.limit is not None:
        rows = rows[: ns.limit]

    n = 0
    bypass = 0
    errors = 0
    fout = open(ns.out, "w", encoding="utf-8") if ns.out else None

    for payload, group in rows:
        n += 1
        url = f"{base}{ep}?payload={quote(payload, safe='')}"
        req = Request(url, headers={"Accept": "application/json"})
        try:
            with urlopen(req, timeout=ns.timeout) as resp:
                body = resp.read().decode("utf-8")
            obj = json.loads(body)
            if not isinstance(obj, dict):
                raise ValueError("invalid_json_shape")
            scored = _unwrap_waf_json(obj)
            blocked = bool(scored.get("blocked"))
            is_bypass = not blocked
            if is_bypass:
                bypass += 1
            row = {
                "payload": payload[:2000],
                "group": group,
                "blocked": blocked,
                "bypass": is_bypass,
                "raw": scored,
            }
            if fout:
                fout.write(json.dumps(row, ensure_ascii=False) + "\n")
        except Exception as e:
            errors += 1
            row = {"payload": payload[:500], "group": group, "error": str(e)}
            if fout:
                fout.write(json.dumps(row, ensure_ascii=False) + "\n")
        if ns.sleep:
            time.sleep(ns.sleep)

    if fout:
        fout.close()

    rate = bypass / n if n else 0.0
    summary = {
        "n_total": n,
        "n_bypass": bypass,
        "n_errors": errors,
        "bypass_rate": rate,
        "base_url": base,
        "evaluate_path": ep,
    }
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0 if errors == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
