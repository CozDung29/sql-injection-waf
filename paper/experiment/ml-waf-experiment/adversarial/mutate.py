import re

from evasion.transformers import (
    case_mix,
    case_upper_keywords,
    comment_inline_mysql,
    comment_inline_mysql_hash,
    comment_slash_star,
    double_url_encode,
    hex_encode,
    null_byte_suffix,
    plus_for_space,
    tab_newline_for_space,
    url_encode,
)


def split_union_select(payload: str) -> str:
    return re.sub(r"(?i)\bunion\s+select\b", "UNION/**/SELECT", payload, count=1)


def mutate_from_blocked(payload: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    steps = [
        ("adv_url_encode", url_encode),
        ("adv_double_url_encode", double_url_encode),
        ("adv_case_mix", case_mix),
        ("adv_case_upper_kw", case_upper_keywords),
        ("adv_comment_mysql", comment_inline_mysql),
        ("adv_comment_hash", comment_inline_mysql_hash),
        ("adv_comment_slash", comment_slash_star),
        ("adv_plus_space", plus_for_space),
        ("adv_tab_space", tab_newline_for_space),
        ("adv_null_suffix", null_byte_suffix),
    ]
    for label, fn in steps:
        try:
            r = fn(payload)
            if r and len(r) < 2000 and r != payload:
                out.append((r, label))
        except Exception:
            pass
    try:
        su = split_union_select(payload)
        if su != payload and len(su) < 2000:
            out.append((su, "adv_split_union"))
    except Exception:
        pass
    try:
        h = hex_encode(payload[:24])
        if len(h) < 400:
            out.append((h, "adv_hex_prefix"))
    except Exception:
        pass
    return out
