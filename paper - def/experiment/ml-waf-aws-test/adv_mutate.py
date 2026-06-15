import json
import re
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parent
_ML_WAF = _ROOT.parent / "ml-waf"
if _ML_WAF.is_dir() and str(_ML_WAF) not in sys.path:
    sys.path.insert(0, str(_ML_WAF))

import evasion.transformers as _T

_FN_REGISTRY = {
    "url_encode": _T.url_encode,
    "url_encode_plus": _T.url_encode_plus,
    "url_encode_quotes_only": _T.url_encode_quotes_only,
    "url_encode_non_alnum": _T.url_encode_non_alnum,
    "triple_url_encode": _T.triple_url_encode,
    "double_url_encode": _T.double_url_encode,
    "case_mix": _T.case_mix,
    "case_upper_keywords": _T.case_upper_keywords,
    "comment_inline_mysql": _T.comment_inline_mysql,
    "comment_inline_mysql_hash": _T.comment_inline_mysql_hash,
    "comment_inline_double_dash": _T.comment_inline_double_dash,
    "comment_slash_star": _T.comment_slash_star,
    "hex_encode": _T.hex_encode,
    "hex_encode_chars": _T.hex_encode_chars,
    "char_concat": _T.char_concat,
    "unicode_escape": _T.unicode_escape,
    "plus_for_space": _T.plus_for_space,
    "tab_newline_for_space": _T.tab_newline_for_space,
    "null_byte_suffix": _T.null_byte_suffix,
    "double_quote_escape": _T.double_quote_escape,
    "backtick_wrap": _T.backtick_wrap,
    "concat_obfuscate": _T.concat_obfuscate,
}

DEFAULT_RULES_PATH = _ROOT / "data" / "mutate_rules.json"


def load_mutate_rules(path: Path | None = None) -> dict[str, Any]:
    p = path or DEFAULT_RULES_PATH
    if not p.is_file():
        raise FileNotFoundError(f"mutate rules not found: {p}")
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def _apply_transform_steps(
    payload: str, rules: dict[str, Any]
) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    max_len = int(rules.get("max_payload_len", 2000))
    for step in rules.get("transform_steps", []):
        label = step["label"]
        fn_name = step["fn"]
        fn = _FN_REGISTRY.get(fn_name)
        if fn is None:
            raise KeyError(f"unknown transform fn: {fn_name!r} (valid: {sorted(_FN_REGISTRY)})")
        try:
            r = fn(payload)
            if r and len(r) < max_len and r != payload:
                out.append((r, label))
        except Exception:
            pass
    return out


def _apply_regex_rules(payload: str, rules: dict[str, Any]) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    max_len = int(rules.get("max_payload_len", 2000))
    for spec in rules.get("regex_rules", []):
        label = spec["label"]
        pattern = spec["pattern"]
        repl = spec["replacement"]
        count = spec.get("count")
        cnt = 0 if count is None else int(count)
        flags = re.IGNORECASE if spec.get("ignore_case") else 0
        try:
            if cnt > 0:
                su = re.sub(pattern, repl, payload, count=cnt, flags=flags)
            else:
                su = re.sub(pattern, repl, payload, flags=flags)
            if su != payload and len(su) < max_len:
                out.append((su, label))
        except Exception:
            pass
    return out


def _hex_prefix(payload: str, rules: dict[str, Any]) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    cfg = rules.get("hex_prefix_rule") or {}
    if not cfg.get("enabled", True):
        return out
    max_len = int(rules.get("max_payload_len", 2000))
    label = cfg.get("label", "adv_hex_prefix")
    n = int(cfg.get("prefix_chars", 24))
    max_hex = int(cfg.get("max_hex_len", 400))
    try:
        h = _T.hex_encode(payload[:n])
        if len(h) < max_hex:
            out.append((h, label))
    except Exception:
        pass
    return out


def mutate_from_blocked(
    payload: str,
    rules: dict[str, Any] | None = None,
    rules_path: Path | None = None,
) -> list[tuple[str, str]]:
    if rules is None:
        rules = load_mutate_rules(rules_path)
    seen: set[tuple[str, str]] = set()
    ordered: list[tuple[str, str]] = []

    def add(pairs: list[tuple[str, str]]) -> None:
        for t, lab in pairs:
            key = (t, lab)
            if key not in seen:
                seen.add(key)
                ordered.append((t, lab))

    add(_apply_transform_steps(payload, rules))
    add(_apply_regex_rules(payload, rules))
    add(_hex_prefix(payload, rules))
    return ordered


_PG_SECOND_LAYER_ALLOW = frozenset(
    {
        "identity",
        "url_encode",
        "double_url_encode",
        "case_mix",
        "case_upper_keywords",
        "comment_inline_mysql",
        "comment_slash_star",
        "plus_for_space",
        "tab_for_space",
        "null_byte_suffix",
        "hex_encode",
    }
)


def all_transforms_for_dialect(payload: str, dialect: str) -> list[tuple[str, str]]:
    from evasion.transformers import all_transforms as _all

    d = (dialect or "postgresql").lower().strip()
    out = _all(payload)
    if d in ("postgresql", "pg", "postgres"):
        return [(t, n) for t, n in out if n not in {"comment_inline_hash"}]
    return out


def second_layer_expand(
    first_layer: list[tuple[str, str]],
    max_inputs: int = 12,
    max_per_input: int = 5,
    total_cap: int = 60,
    sql_dialect: str = "postgresql",
) -> list[tuple[str, str]]:
    from evasion.transformers import all_transforms

    d = (sql_dialect or "postgresql").lower().strip()
    is_pg = d in ("postgresql", "pg", "postgres")
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for p, lab in first_layer[:max_inputs]:
        try:
            gen = all_transforms(p)
        except Exception:
            continue
        n = 0
        for t, tname in gen:
            if is_pg and tname not in _PG_SECOND_LAYER_ALLOW:
                continue
            if t == p or len(t) > 2000:
                continue
            if t in seen:
                continue
            seen.add(t)
            out.append((t, f"mut_{lab}__{tname}"))
            n += 1
            if n >= max_per_input or len(out) >= total_cap:
                break
        if len(out) >= total_cap:
            break
    return out


def merge_adv_into_variants(
    variants: list[tuple[str, str]],
    seed: str,
    rules_path: Path | None,
    mutate_max: int = 80,
    second_layer: bool = True,
    second_layer_cap: int = 50,
    sql_dialect: str = "postgresql",
) -> list[tuple[str, str]]:
    if rules_path is None or not rules_path.is_file():
        return variants
    try:
        rules = load_mutate_rules(rules_path)
    except OSError:
        return variants
    seen: set[str] = {p for p, _ in variants}
    out = list(variants)
    pairs = mutate_from_blocked(seed, rules=rules)[:mutate_max]
    for p, lab in pairs:
        if p and p not in seen:
            seen.add(p)
            out.append((p, f"mut_{lab}"))
    if second_layer and pairs:
        extra = second_layer_expand(
            pairs,
            max_inputs=min(12, len(pairs)),
            max_per_input=5,
            total_cap=second_layer_cap,
            sql_dialect=sql_dialect,
        )
        for p, lab in extra:
            if p not in seen:
                seen.add(p)
                out.append((p, lab))
    return out
