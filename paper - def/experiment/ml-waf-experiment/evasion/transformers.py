import re
from urllib.parse import quote, quote_plus

def url_encode(s: str) -> str:
    return quote(s, safe="")

def double_url_encode(s: str) -> str:
    return quote(quote(s, safe=""), safe="")

def case_mix(s: str) -> str:
    out = []
    for i, c in enumerate(s):
        if c.isalpha():
            out.append(c.upper() if i % 2 == 0 else c.lower())
        else:
            out.append(c)
    return "".join(out)

def case_upper_keywords(s: str) -> str:
    for w in ["select", "union", "from", "where", "or", "and", "insert", "update", "delete", "drop", "exec", "sleep", "benchmark"]:
        s = re.sub(re.escape(w), w.upper(), s, flags=re.I)
    return s

def comment_inline_mysql(s: str) -> str:
    return re.sub(r"\s+", "/**/", s)

def comment_inline_mysql_hash(s: str) -> str:
    return re.sub(r"\s+", "#", s)

def comment_inline_double_dash(s: str) -> str:
    return re.sub(r"\s+", "-- ", s)

def comment_slash_star(s: str) -> str:
    return re.sub(r"\s+", "/*x*/", s)

def hex_encode(s: str) -> str:
    return "0x" + s.encode("utf-8").hex()

def hex_encode_chars(s: str) -> str:
    out = []
    for c in s:
        if c.isalnum() or c in " _-":
            out.append(c)
        else:
            out.append(f"0x{c.encode('utf-8').hex()}")
    return "".join(out)

def char_concat(s: str) -> str:
    parts = [f"CHAR({ord(c)})" for c in s[:32]]
    return "CONCAT(" + ",".join(parts) + ")" if parts else s

def unicode_escape(s: str) -> str:
    out = []
    for c in s:
        if ord(c) < 128:
            out.append(c)
        else:
            out.append(f"\\u{ord(c):04x}")
    return "".join(out)

def plus_for_space(s: str) -> str:
    return s.replace(" ", "+")

def tab_newline_for_space(s: str) -> str:
    return re.sub(r"\s+", "\t", s)

def null_byte_suffix(s: str) -> str:
    return s + "%00"

def double_quote_escape(s: str) -> str:
    return s.replace("'", "''")

def backtick_wrap(s: str) -> str:
    return "`" + s.replace(" ", "` `") + "`"

def concat_obfuscate(s: str) -> str:
    if "=" in s:
        a, b = s.split("=", 1)
        return f"{a}=CONCAT({repr(b[:1])},{repr(b[1:])})"
    return s

def all_transforms(payload: str) -> list[tuple[str, str]]:
    out = []
    t = [
        ("identity", lambda x: x),
        ("url_encode", url_encode),
        ("double_url_encode", double_url_encode),
        ("case_mix", case_mix),
        ("case_upper_keywords", case_upper_keywords),
        ("comment_inline_mysql", comment_inline_mysql),
        ("comment_inline_hash", comment_inline_mysql_hash),
        ("comment_slash_star", comment_slash_star),
        ("plus_for_space", plus_for_space),
        ("tab_for_space", tab_newline_for_space),
        ("null_byte_suffix", null_byte_suffix),
    ]
    for name, fn in t:
        try:
            r = fn(payload)
            if r and r != payload or name == "identity":
                out.append((r, name))
        except Exception:
            pass
    try:
        h = hex_encode(payload[:20])
        if len(h) < 200:
            out.append((h, "hex_encode"))
    except Exception:
        pass
    return out

TRANSFORM_NAMES = [
    "identity", "url_encode", "double_url_encode", "case_mix", "case_upper_keywords",
    "comment_inline_mysql", "comment_inline_hash", "comment_slash_star",
    "plus_for_space", "tab_for_space", "null_byte_suffix", "hex_encode",
]
