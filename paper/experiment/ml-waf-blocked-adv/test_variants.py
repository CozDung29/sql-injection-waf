import argparse
import json
import sys
import time
from pathlib import Path

try:
    import requests
except ImportError:
    print("pip install requests", file=sys.stderr)
    sys.exit(1)

from http_probe import HEADERS, build_url, is_bypass

DATA_DIR = Path(__file__).resolve().parent / "data"
DEFAULT_IN = DATA_DIR / "adversarial_from_blocked.jsonl"
DEFAULT_OUT = DATA_DIR / "test_results.jsonl"


def load_variant_lines(path: Path, tail: int | None) -> list[dict]:
    lines = path.read_text(encoding="utf-8").splitlines()
    if tail is not None and tail > 0:
        lines = lines[-tail:]
    rows = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            o = json.loads(line)
            vp = o.get("variant_payload")
            if vp:
                rows.append(o)
        except json.JSONDecodeError:
            continue
    return rows


def load_completed_payloads(path: Path) -> set[str]:
    done: set[str] = set()
    if not path.is_file():
        return done
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            o = json.loads(line)
        except json.JSONDecodeError:
            continue
        vp = o.get("variant_payload")
        res = o.get("result")
        if vp and res in ("bypass", "blocked"):
            done.add(vp)
    return done


def classify(resp) -> str:
    if is_bypass(resp):
        return "bypass"
    return "blocked"


MSG_401 = (
    "\nStopped: HTTP 401 Unauthorized (token expired or invalid). "
    "Update BEARER in ml-waf/evasion/curl_bypass_f5.py and rerun."
)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="HTTP-test variant_payload lines from expand_from_blocked output (same target as ml-waf curl_bypass_f5)."
    )
    ap.add_argument("--in", dest="in_path", type=Path, default=DEFAULT_IN, help="jsonl from expand_from_blocked.py")
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT, help="append test results jsonl")
    ap.add_argument("--tail", type=int, default=None, metavar="N", help="only last N lines of --in")
    ap.add_argument("--max-tests", type=int, default=None, metavar="N", help="stop after N HTTP GETs")
    ap.add_argument("--sleep", type=float, default=0.0, help="seconds between requests")
    ap.add_argument(
        "--no-stop-on-401",
        action="store_true",
        help="Do not stop when HTTP 401 (default: stop like ml-waf run_until_bypass).",
    )
    ap.add_argument(
        "--resume",
        action="store_true",
        help="Skip variant_payload already completed (bypass/blocked) in --out; retry 401/error only.",
    )
    ns = ap.parse_args(argv)

    if not ns.in_path.is_file():
        print(f"Not found: {ns.in_path} (run expand_from_blocked.py first)", file=sys.stderr)
        return 1

    rows = load_variant_lines(ns.in_path, ns.tail)
    done_vp: set[str] = set()
    if ns.resume:
        done_vp = load_completed_payloads(ns.out)
        before = len(rows)
        rows = [o for o in rows if o.get("variant_payload") not in done_vp]
        print(f"Resume: skipped {before - len(rows)} already done (bypass/blocked in {ns.out.name}), {len(rows)} left")
    ns.out.parent.mkdir(parents=True, exist_ok=True)

    tested = 0
    summary = {"bypass": 0, "blocked": 0, "unauthorized": 0, "error": 0}
    stopped_on_401 = False

    with open(ns.out, "a", encoding="utf-8") as fout:
        for o in rows:
            if ns.max_tests is not None and tested >= ns.max_tests:
                break
            payload = o["variant_payload"]
            url = build_url(payload)
            try:
                r = requests.get(url, headers=HEADERS, timeout=12)
            except requests.RequestException as e:
                rec = {
                    **{k: v for k, v in o.items() if k in ("adv_label", "blocked_source_name", "variant_payload")},
                    "http_status": None,
                    "result": "error",
                    "error": str(e)[:500],
                }
                fout.write(json.dumps(rec, ensure_ascii=False) + "\n")
                summary["error"] += 1
                tested += 1
                if ns.sleep:
                    time.sleep(ns.sleep)
                continue

            if r.status_code == 401:
                body = (r.text or "")[:240]
                rec = {
                    **{k: v for k, v in o.items() if k in ("adv_label", "blocked_source_name", "variant_payload")},
                    "http_status": 401,
                    "result": "unauthorized",
                    "body_snip": body.replace("\n", " ")[:240],
                }
                fout.write(json.dumps(rec, ensure_ascii=False) + "\n")
                tested += 1
                summary["unauthorized"] = summary.get("unauthorized", 0) + 1
                print(f"  [{tested}] unauthorized HTTP 401 {o.get('adv_label', '')}")
                if not ns.no_stop_on_401:
                    print(MSG_401)
                    stopped_on_401 = True
                    break
                if ns.sleep:
                    time.sleep(ns.sleep)
                continue

            result = classify(r)
            summary[result] = summary.get(result, 0) + 1
            body = (r.text or "")[:240]
            rec = {
                **{k: v for k, v in o.items() if k in ("adv_label", "blocked_source_name", "variant_payload")},
                "http_status": r.status_code,
                "result": result,
                "body_snip": body.replace("\n", " ")[:240],
            }
            fout.write(json.dumps(rec, ensure_ascii=False) + "\n")
            tested += 1
            print(f"  [{tested}] {result} HTTP {r.status_code} {o.get('adv_label', '')}")

            if ns.sleep:
                time.sleep(ns.sleep)

    print(f"Done. HTTP attempts: {tested} -> {ns.out.resolve()}")
    print(f"Summary: {summary}")
    if stopped_on_401:
        print("Exit: stopped on HTTP 401 (same behavior as ml-waf evasion/run_until_bypass.py).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
