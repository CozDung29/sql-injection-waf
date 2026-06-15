import re
from urllib.parse import quote

from rules.modsecurity_sqli_regex import count_matches as modsec_sqli_count


def _raw_lengths(req):
    path = req.get("path", "") or ""
    query = req.get("query", "") or ""
    body = req.get("body", "") or ""
    path_len = len(path)
    query_len = len(query)
    body_len = len(body)
    return path_len, query_len, body_len


def _count_special(s: str, chars: str) -> int:
    return sum(s.count(c) for c in chars)


def _count_sql_like(s: str) -> int:
    pattern = r"(\bOR\b|\bAND\b|'|\"|;|--|/\*|\*/|union|select|insert|update|delete|drop|exec|execute)"
    return len(re.findall(pattern, s, re.I))


def _count_xss_like(s: str) -> int:
    pattern = r"(<|>|script|onerror|onload|javascript:|vbscript:)"
    return len(re.findall(pattern, s, re.I))


def _count_path_traversal(s: str) -> int:
    return s.count("..") + s.count("/..") + s.count("\\")


def _encoding_ratio(s: str) -> float:
    if not s:
        return 0.0
    try:
        encoded = quote(s, safe="")
        return len(encoded) / max(len(s), 1)
    except Exception:
        return 0.0


def _digit_ratio(s: str) -> float:
    if not s:
        return 0.0
    return sum(c.isdigit() for c in s) / len(s)


def _space_ratio(s: str) -> float:
    if not s:
        return 0.0
    return s.count(" ") / len(s)


def _header_count(req) -> int:
    h = req.get("headers") or {}
    return len(h) if isinstance(h, dict) else 0


def extract(req: dict) -> list[float]:
    path = (req.get("path") or "") + (req.get("query") or "")
    body = req.get("body") or ""
    full = path + " " + body
    path_only = req.get("path") or ""
    path_len, query_len, body_len = _raw_lengths(req)
    sql_score = modsec_sqli_count(full) + _count_sql_like(full)
    xss_score = _count_xss_like(full)
    path_traversal = _count_path_traversal(path_only)
    special_sql = _count_special(full, "'\";--")
    special_xss = _count_special(full, "<>")
    enc_ratio = _encoding_ratio(full)
    digit_ratio = _digit_ratio(full)
    space_ratio = _space_ratio(full)
    num_headers = _header_count(req)
    total_len = path_len + query_len + body_len
    return [
        float(path_len),
        float(query_len),
        float(body_len),
        float(total_len),
        float(sql_score),
        float(xss_score),
        float(path_traversal),
        float(special_sql),
        float(special_xss),
        enc_ratio,
        digit_ratio,
        space_ratio,
        float(num_headers),
    ]


FEATURE_NAMES = [
    "path_len",
    "query_len",
    "body_len",
    "total_len",
    "sql_score",
    "xss_score",
    "path_traversal",
    "special_sql",
    "special_xss",
    "encoding_ratio",
    "digit_ratio",
    "space_ratio",
    "num_headers",
]
