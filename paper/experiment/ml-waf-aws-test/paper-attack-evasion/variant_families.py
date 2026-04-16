from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

_SPAWN_SUFFIX_RULES: list[tuple[str, str]] = [
    (r"(?i)identity", "spawn_identity"),
    (r"(?i)case_mix", "spawn_case_mix"),
    (r"(?i)null_byte|null", "spawn_null_byte"),
    (r"(?i)hex", "spawn_hex_style"),
    (r"(?i)unicode", "spawn_unicode"),
    (r"(?i)comment", "spawn_comment"),
    (r"(?i)concat", "spawn_concat"),
    (r"(?i)encode|percent", "spawn_encoding"),
    (r"(?i)tab|space|newline|whitespace", "spawn_whitespace"),
]

_DEFAULT_REGEX_RULES: list[tuple[str, str]] = [
    (r"^g\d+_", "multi_generation"),
    (r"^aws_", "aws_dialect_variants"),
    (r"^account_", "hex_account_style"),
    (r"(?i)fullwidth", "unicode_fullwidth"),
    (r"(?i)unicode", "unicode_escape"),
    (r"(?i)double_?enc|double_encoded", "nested_percent_encoding"),
    (r"(?i)triple", "nested_percent_encoding"),
    (r"(?i)hex", "hex_encoding"),
    (r"(?i)comment", "sql_comment_obfuscation"),
    (r"(?i)concat|char\s*\(", "concat_char_obfuscation"),
    (r"(?i)null_byte|%00", "null_byte_suffix"),
    (r"(?i)backtick|`", "identifier_quotes"),
    (r"(?i)^original$", "baseline_seed"),
    (r"(?i)plus_space|tab|newline|vtab|cr\b|ff\b|lf\b|pre_.*encoded|one_space|whitespace|space_to_", "whitespace_and_delimiters"),
    (r"(?i)encode|percent|pct|url", "percent_encoding_variants"),
    (r"(?i)or_|union|select|where", "keyword_surface_variants"),
]

_MATCHER: tuple[list[tuple[re.Pattern[str], str]], list[tuple[str, str]]] | None = None


def _load_json_rules(path: Path | None) -> dict[str, Any]:
    p = path
    if p is None:
        p = Path(__file__).resolve().parent / "variant_family_rules.json"
    if not p.is_file():
        return {}
    try:
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def build_family_matcher(
    extra_rules_path: Path | None = None,
) -> tuple[list[tuple[re.Pattern[str], str]], list[tuple[str, str]]]:
    data = _load_json_rules(extra_rules_path)
    regex_rows: list[tuple[str, str]] = list(_DEFAULT_REGEX_RULES)
    for row in data.get("regex_rules") or []:
        pat = row.get("pattern")
        fam = row.get("family")
        if isinstance(pat, str) and isinstance(fam, str) and pat.strip():
            regex_rows.insert(0, (pat, fam))
    prefix_rows: list[tuple[str, str]] = []
    for row in data.get("prefix_rules") or []:
        px = row.get("prefix")
        fam = row.get("family")
        if isinstance(px, str) and isinstance(fam, str) and px.strip():
            prefix_rows.append((px, fam))
    compiled: list[tuple[re.Pattern[str], str]] = []
    for pat, fam in regex_rows:
        try:
            compiled.append((re.compile(pat), fam))
        except re.error:
            continue
    return compiled, prefix_rows


def _get_default_matcher() -> tuple[list[tuple[re.Pattern[str], str]], list[tuple[str, str]]]:
    global _MATCHER
    if _MATCHER is None:
        _MATCHER = build_family_matcher(None)
    return _MATCHER


def _spawn_family_from_rest(rest: str) -> str:
    for pat, fam in _SPAWN_SUFFIX_RULES:
        if re.search(pat, rest):
            return fam
    return "spawn_other"


def variant_family(variant: str, rules_path: Path | None = None) -> str:
    v = variant.strip()
    if not v:
        return "unknown"
    m = re.match(r"^b\d+_(.+)$", v)
    if m:
        return _spawn_family_from_rest(m.group(1))
    if rules_path is not None:
        compiled, prefixes = build_family_matcher(rules_path)
    else:
        compiled, prefixes = _get_default_matcher()
    for px, fam in prefixes:
        if v.startswith(px):
            return fam
    for rx, fam in compiled:
        if rx.search(v):
            return fam
    return "other_misc"
