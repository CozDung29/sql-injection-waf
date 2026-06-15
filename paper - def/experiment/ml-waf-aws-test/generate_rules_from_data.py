import argparse
import json
import math
import re
import sys
from collections import Counter
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

try:
    import numpy as np
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.model_selection import train_test_split
    from sklearn.pipeline import Pipeline
except ImportError:
    print("pip install -r requirements.txt (needs numpy, scikit-learn)", file=sys.stderr)
    sys.exit(1)

ROOT = Path(__file__).resolve().parent
DEFAULT_DATA_DIRS = [ROOT / "data", ROOT.parent / "ml-waf" / "data"]
DEFAULT_MUTATE_RULES = ROOT / "data" / "mutate_rules.json"

TRANSFORM_FN_REGEX: dict[str, list[str]] = {
    "url_encode": [r"%27", r"%22", r"%3[Dd]", r"%2[Ff]"],
    "url_encode_plus": [r"%27", r"%20"],
    "url_encode_quotes_only": [r"%27"],
    "url_encode_non_alnum": [r"%[0-9A-Fa-f]{2}"],
    "double_url_encode": [r"%25[0-9A-Fa-f]{2}"],
    "triple_url_encode": [r"%25%25%25"],
    "case_upper_keywords": [r"\b(?:SELECT|UNION|FROM|WHERE|OR|AND)\b"],
    "comment_inline_mysql": [r"/\*\*/"],
    "comment_inline_mysql_hash": [r"#"],
    "comment_inline_double_dash": [r"--\s"],
    "comment_slash_star": [r"/\*x\*/"],
    "hex_encode": [r"0x[0-9a-fA-F]{16,}"],
    "hex_encode_chars": [r"(?:0x[0-9a-fA-F]{2}){4,}"],
    "char_concat": [r"\bCHAR\s*\(", r"\bCONCAT\s*\("],
    "unicode_escape": [r"\\u[0-9a-fA-F]{4}"],
    "plus_for_space": [r"(?i)\+(?:or|and|union|select)\+"],
    "tab_newline_for_space": [r"\t"],
    "null_byte_suffix": [r"%00"],
    "double_quote_escape": [r"''"],
    "backtick_wrap": [r"`"],
    "concat_obfuscate": [r"=\s*CONCAT\s*\("],
}

TRANSFORM_FN_BYTES: dict[str, list[str]] = {
    "comment_inline_mysql": ["/**/"],
    "comment_slash_star": ["/*x*/"],
    "null_byte_suffix": ["%00"],
}


def load_mutate_rules(path: Path | None) -> dict | None:
    p = path or DEFAULT_MUTATE_RULES
    if not p.is_file():
        return None
    try:
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def collect_patterns_from_mutate_rules(rules: dict) -> tuple[list[str], list[str], list[str]]:
    regex_out: list[str] = []
    labels_regex: list[str] = []
    for spec in rules.get("regex_rules") or []:
        pat = spec.get("pattern")
        if isinstance(pat, str) and pat.strip():
            regex_out.append(pat.strip())
            labels_regex.append(str(spec.get("label") or "regex_rule"))

    seen_r: set[str] = set()
    ordered_r: list[str] = []
    ordered_lbl: list[str] = []
    for p, lb in zip(regex_out, labels_regex):
        k = p.lower()
        if k in seen_r:
            continue
        seen_r.add(k)
        ordered_r.append(p)
        ordered_lbl.append(lb)

    for step in rules.get("transform_steps") or []:
        fn = step.get("fn")
        if not isinstance(fn, str) or not fn:
            continue
        for rx in TRANSFORM_FN_REGEX.get(fn, []):
            k = rx.lower()
            if k in seen_r:
                continue
            seen_r.add(k)
            ordered_r.append(rx)
            ordered_lbl.append(str(step.get("label") or fn))

    hex_cfg = rules.get("hex_prefix_rule") or {}
    if hex_cfg.get("enabled", False):
        n = int(hex_cfg.get("prefix_chars", 24))
        min_hex = max(16, n * 2 - 8)
        rx = rf"0x[0-9a-fA-F]{{{min_hex},}}"
        if rx.lower() not in seen_r:
            seen_r.add(rx.lower())
            ordered_r.append(rx)
            ordered_lbl.append(str(hex_cfg.get("label") or "hex_prefix_rule"))

    byte_out: list[str] = []
    for step in rules.get("transform_steps") or []:
        fn = step.get("fn")
        if not isinstance(fn, str):
            continue
        for b in TRANSFORM_FN_BYTES.get(fn, []):
            if b and b not in byte_out:
                byte_out.append(b)

    return ordered_r, byte_out, ordered_lbl


def raw_regex_to_chunks(patterns: list[str], max_regex_bytes: int) -> list[str]:
    chunks: list[list[str]] = []
    cur: list[str] = []
    cur_bytes = 0
    for raw in patterns:
        part = raw.strip()
        if not part:
            continue
        need = _regex_string_byte_len(part)
        sep = 1 if cur else 0
        if cur and cur_bytes + sep + need > max_regex_bytes:
            chunks.append(cur)
            cur = [part]
            cur_bytes = need
        else:
            if cur:
                cur_bytes += 1
            cur.append(part)
            cur_bytes += need
    if cur:
        chunks.append(cur)
    out = []
    for group in chunks:
        body = "|".join(group)
        out.append(f"(?:{body})")
    return out


def build_compact_regex_rule_raw(
    patterns: list[str],
    name: str,
    priority: int,
    metric_name: str,
    max_regex_bytes: int,
) -> dict | None:
    chunks = raw_regex_to_chunks(patterns, max_regex_bytes=max_regex_bytes)
    if not chunks:
        return None
    stmts = [regex_match_statement(rx) for rx in chunks]
    return build_aws_byte_rule(stmts, name=name, priority=priority, metric_name=metric_name)


def _load_jsonl(path: Path) -> list[dict]:
    rows = []
    if not path.is_file():
        return rows
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def _payload_from_url_snip(url: str) -> str | None:
    try:
        q = urlparse(url).query
        if not q:
            return None
        d = parse_qs(q, keep_blank_values=True)
        for _k, vals in d.items():
            if vals and vals[0]:
                return vals[0]
    except (ValueError, TypeError):
        pass
    return None


def collect_labeled_payloads(data_dirs: list[Path]) -> tuple[list[str], list[str], list[str]]:
    bypass: list[str] = []
    blocked: list[str] = []
    benign: list[str] = []

    for base in data_dirs:
        if not base.is_dir():
            continue
        bl_path = base / "bypass_learned.jsonl"
        for o in _load_jsonl(bl_path):
            p = o.get("payload")
            if isinstance(p, str) and p.strip():
                bypass.append(p)

        bk_path = base / "blocked_learned.jsonl"
        for o in _load_jsonl(bk_path):
            p = o.get("payload")
            if isinstance(p, str) and p.strip():
                blocked.append(p)

        probe_path = base / "aws_probe_results.jsonl"
        for o in _load_jsonl(probe_path):
            r = o.get("result")
            if r == "bypass":
                p = o.get("payload")
                if not isinstance(p, str) or not p.strip():
                    p = _payload_from_url_snip(o.get("url_snip") or "")
                if isinstance(p, str) and p.strip():
                    bypass.append(p)
            elif r == "blocked":
                p = o.get("payload")
                if not isinstance(p, str) or not p.strip():
                    p = _payload_from_url_snip(o.get("url_snip") or "")
                if isinstance(p, str) and p.strip():
                    blocked.append(p)

        adv_path = base / "adversarial_report.jsonl"
        for o in _load_jsonl(adv_path):
            if o.get("f5") == "bypass":
                p = o.get("payload")
                if isinstance(p, str) and p.strip():
                    bypass.append(p)
            elif o.get("f5") == "block":
                p = o.get("payload")
                if isinstance(p, str) and p.strip():
                    blocked.append(p)

        benign_path = base / "benign.json"
        if benign_path.is_file():
            try:
                with open(benign_path, encoding="utf-8") as f:
                    arr = json.load(f)
                if isinstance(arr, list):
                    for req in arr:
                        if not isinstance(req, dict):
                            continue
                        q = str(req.get("query") or "")
                        b = str(req.get("body") or "")
                        s = (q + " " + b).strip()
                        if s:
                            benign.append(s)
            except (json.JSONDecodeError, OSError):
                pass

    def _dedup(xs: list[str]) -> list[str]:
        seen: set[str] = set()
        out = []
        for x in xs:
            if x in seen:
                continue
            seen.add(x)
            out.append(x)
        return out

    return _dedup(bypass), _dedup(blocked), benign


def collect_bypass_payloads(data_dirs: list[Path]) -> list[str]:
    bypass: list[str] = []
    for base in data_dirs:
        if not base.is_dir():
            continue
        for o in _load_jsonl(base / "bypass_learned.jsonl"):
            p = o.get("payload")
            if isinstance(p, str) and p.strip():
                bypass.append(p)
        for o in _load_jsonl(base / "aws_probe_results.jsonl"):
            if o.get("result") != "bypass":
                continue
            p = o.get("payload")
            if not isinstance(p, str) or not p.strip():
                p = _payload_from_url_snip(o.get("url_snip") or "")
            if isinstance(p, str) and p.strip():
                bypass.append(p)
        for o in _load_jsonl(base / "adversarial_report.jsonl"):
            if o.get("f5") != "bypass":
                continue
            p = o.get("payload")
            if isinstance(p, str) and p.strip():
                bypass.append(p)

    def _dedup(xs: list[str]) -> list[str]:
        seen: set[str] = set()
        out = []
        for x in xs:
            if x in seen:
                continue
            seen.add(x)
            out.append(x)
        return out

    return _dedup(bypass)


def strip_id_remap_prefix(payload: str) -> str:
    return re.sub(r"^[A-Za-z_][A-Za-z0-9_]*", "", payload, count=1)


def normalize_for_mining(payload: str) -> str:
    m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)", payload)
    if not m:
        return payload
    seg = m.group(1)
    if re.search(r"(?i)project", seg):
        return payload[len(seg) :]
    if re.search(r"(?i)demo", seg) and len(seg) >= 6:
        return payload[len(seg) :]
    return payload


def normalize_for_mining_deep(payload: str, passes: int = 3) -> str:
    p = payload
    for _ in range(passes):
        q = normalize_for_mining(p)
        if q == p:
            break
        p = q
    return p


def is_remap_api_fragment(s: str) -> bool:
    if not s or len(s) > 120:
        return False
    if re.search(
        r"(?i)(?:^|[^a-z])roject(?:%|\'|%25|$|[0-9])",
        s,
    ):
        return True
    if re.search(r"(?i)demo_project|o_project|project%27|project%25|project\'", s):
        return True
    if re.search(r"(?i)(?:^|_)emo_[a-z0-9]", s) and len(s) < 40:
        return True
    if re.search(r"(?i)(?:^|[^a-z0-9])ect%27", s):
        return True
    return False


def generalize_substring_to_regex(sub: str) -> str | None:
    sub = sub.strip()
    if not sub or len(sub) < 4:
        return None
    if len(sub.encode("utf-8")) > 80:
        return None
    if re.fullmatch(r"[0-9a-fA-F]+", sub, re.I) and len(sub) < 20:
        return None
    if re.fullmatch(r"[0-9]+", sub) and len(sub) < 12:
        return None
    if "%00" in sub or re.search(r"0{2}%0", sub):
        return r"%00(?:%00)*"
    m = re.fullmatch(r"(0x)([0-9a-fA-F]+)", sub, re.I)
    if m:
        L = len(m.group(2))
        lo = max(10, min(L, 48))
        return f"0x[0-9a-fA-F]{{{lo},}}"
    m = re.fullmatch(r"(x)([0-9a-fA-F]+)", sub, re.I)
    if m and len(m.group(2)) >= 10:
        L = len(m.group(2))
        lo = max(10, min(L, 48))
        return f"x[0-9a-fA-F]{{{lo},}}"
    if re.fullmatch(r"%[0-9A-Fa-f]{2}(?:%[0-9A-Fa-f]{2})+", sub):
        return r"(?:%[0-9A-Fa-f]{2}){4,}"
    if re.match(r"^[ -~]{4,}$", sub) and not re.search(r"[0-9a-fA-F]{20,}", sub):
        return re.escape(sub)
    return None


def mine_bypass_substrings_for_support(
    bypass_norm: list[str],
    min_len: int,
    max_len: int,
    min_support: int,
    max_windows_per_payload: int,
) -> Counter[str]:
    doc_freq: Counter[str] = Counter()
    for p in bypass_norm:
        n = len(p)
        if n < min_len:
            continue
        windows: set[str] = set()
        for L in range(min_len, min(max_len, n) + 1):
            for i in range(0, n - L + 1):
                s = p[i : i + L]
                if len(s.encode("utf-8")) > 50:
                    continue
                windows.add(s)
        wl = sorted(windows)
        if len(wl) > max_windows_per_payload:
            step = max(1, len(wl) // max_windows_per_payload)
            wl = wl[::step][:max_windows_per_payload]
        for w in wl:
            doc_freq[w] += 1
    return Counter({k: v for k, v in doc_freq.items() if v >= min_support})


def structural_signatures_from_bypass_norm(
    bypass_norm: list[str], min_support: int
) -> list[str]:
    if not bypass_norm:
        return []
    out: list[str] = []
    rx0 = re.compile(r"0x[0-9a-fA-F]{16,}", re.I)
    if sum(1 for p in bypass_norm if rx0.search(p)) >= min_support:
        out.append(r"0x[0-9a-fA-F]{16,}")
    rxx = re.compile(r"(?:^|[^0-9A-Fa-f])x[0-9a-fA-F]{16,}", re.I)
    if sum(1 for p in bypass_norm if rxx.search(p)) >= min_support:
        out.append(r"x[0-9a-fA-F]{16,}")
    if sum(1 for p in bypass_norm if "%00" in p) >= min_support:
        out.append(r"%00(?:%00)*")
    return out


def bypass_char_ngrams_as_regex(
    bypass_norm: list[str], min_df: int, max_terms: int
) -> list[str]:
    if len(bypass_norm) < 4:
        return []
    min_df_v = max(2, min(min_df, len(bypass_norm) // 3))
    vec = TfidfVectorizer(
        analyzer="char_wb",
        ngram_range=(4, 8),
        max_features=4000,
        min_df=min_df_v,
        max_df=0.95,
    )
    try:
        X = vec.fit_transform(bypass_norm)
    except ValueError:
        return []
    names = vec.get_feature_names_out()
    scores = np.asarray(X.mean(axis=0)).ravel()
    idx = np.argsort(scores)[::-1][: max_terms * 2]
    out: list[str] = []
    for i in idx:
        tok = str(names[int(i)])
        if len(tok) < 4 or len(tok) > 40:
            continue
        if not re.match(r"^[ -~]+$", tok):
            continue
        if re.fullmatch(r"[0-9a-fA-F]+", tok, re.I):
            continue
        if re.fullmatch(r"[0-9]+", tok):
            continue
        if is_remap_api_fragment(tok):
            continue
        g = generalize_substring_to_regex(tok)
        if g is None:
            g = re.escape(tok)
        if is_remap_api_fragment(g):
            continue
        if g not in out:
            out.append(g)
        if len(out) >= max_terms:
            break
    return out


def _drop_sloppy_null_escapes(patterns: list[str]) -> list[str]:
    out: list[str] = []
    for rx in patterns:
        if rx != r"%00(?:%00)*" and "%00" in rx and "\\" in rx:
            continue
        out.append(rx)
    return out


def build_bypass_generalized_regexes(
    bypass: list[str],
    min_support_ratio: float,
    min_len: int,
    max_len: int,
    max_patterns: int,
    ngram_min_df: int,
    ngram_max_terms: int,
) -> tuple[list[str], dict]:
    meta: dict = {"bypass_inputs": len(bypass), "notes": []}
    if len(bypass) < 2:
        return [], meta

    norm = [normalize_for_mining_deep(p) for p in bypass]
    min_support = max(2, int(math.ceil(min_support_ratio * len(bypass))))
    min_support = min(min_support, len(bypass))
    meta["min_support_docs"] = min_support

    seen: set[str] = set()
    ordered: list[str] = []

    def push_rx(rx: str) -> None:
        if re.match(r"^0x\[0-9a-fA-F\]\{\d+,\}$", rx):
            rx = r"0x[0-9a-fA-F]{16,}"
        k = rx.lower()
        if k in seen:
            return
        seen.add(k)
        ordered.append(rx)

    for rx in structural_signatures_from_bypass_norm(norm, min_support):
        push_rx(rx)

    doc_sup = mine_bypass_substrings_for_support(
        norm, min_len, max_len, min_support, max_windows_per_payload=350
    )
    scored = sorted(doc_sup.items(), key=lambda x: (-x[1], -len(x[0])))
    for sub, sup in scored[: max_patterns * 3]:
        if len(ordered) >= max_patterns * 2:
            break
        g = generalize_substring_to_regex(sub)
        if g:
            push_rx(g)

    for g in bypass_char_ngrams_as_regex(
        norm, min_df=ngram_min_df, max_terms=ngram_max_terms
    ):
        if len(ordered) >= max_patterns * 2:
            break
        push_rx(g)

    ordered = _drop_sloppy_null_escapes(ordered)
    meta["distinct_patterns"] = len(ordered)
    return ordered[:max_patterns], meta


def _contains(s: str, sub: str) -> bool:
    return sub in s


def mine_substrings(
    blocked: list[str],
    bypass: list[str],
    benign: list[str],
    min_len: int,
    max_len: int,
    min_support: int,
    max_bypass_ratio: float,
) -> list[tuple[str, float, int, int]]:
    bypass_set = [normalize_for_mining_deep(p) for p in bypass]
    benign_joined = (
        " ".join(normalize_for_mining_deep(b) for b in benign) if benign else ""
    )

    def bypass_hits(sub: str) -> int:
        return sum(1 for p in bypass_set if _contains(p, sub))

    def benign_hits(sub: str) -> int:
        if not benign_joined:
            return 0
        return benign_joined.count(sub)

    candidates: Counter[str] = Counter()
    max_windows_per_payload = 400
    for p in (normalize_for_mining_deep(x) for x in blocked):
        n = len(p)
        if n < min_len:
            continue
        windows: list[tuple[int, int]] = []
        for L in range(min_len, min(max_len, n) + 1):
            for i in range(0, n - L + 1):
                windows.append((i, L))
        if len(windows) > max_windows_per_payload:
            step = max(1, len(windows) // max_windows_per_payload)
            windows = windows[::step][:max_windows_per_payload]
        for i, L in windows:
            s = p[i : i + L]
            if len(s.encode("utf-8")) > 50:
                continue
            if is_remap_api_fragment(s):
                continue
            candidates[s] += 1

    scored: list[tuple[str, float, int, int]] = []
    for sub, bc in candidates.items():
        if is_remap_api_fragment(sub):
            continue
        if bc < min_support:
            continue
        bh = bypass_hits(sub)
        if bh / max(bc, 1) > max_bypass_ratio:
            continue
        if benign and benign_hits(sub) > 0:
            continue
        score = float(bc) * (1.0 / (1.0 + bh))
        scored.append((sub, score, bc, bh))

    scored.sort(key=lambda x: (-x[1], -len(x[0])))
    picked: list[tuple[str, float, int, int]] = []
    for item in scored:
        sub, sc, bc, bh = item
        if any(
            _contains(sub, p[0]) and sub != p[0] for p in picked
        ):
            continue
        if any(
            _contains(p[0], sub) and p[0] != sub for p in picked
        ):
            continue
        picked.append(item)
    return picked


def train_linear_ngrams(
    bypass: list[str], blocked: list[str], max_features: int, random_state: int
) -> tuple[list[tuple[str, float]], dict | None]:
    bypass_n = [normalize_for_mining_deep(p) for p in bypass]
    blocked_n = [normalize_for_mining_deep(p) for p in blocked]
    y = np.array([0] * len(bypass_n) + [1] * len(blocked_n))
    X_text = bypass_n + blocked_n
    if len(X_text) < 8 or len(np.unique(y)) < 2:
        return [], None

    pipe = Pipeline(
        [
            (
                "tfidf",
                TfidfVectorizer(
                    analyzer="char_wb",
                    ngram_range=(4, 7),
                    max_features=max_features,
                    min_df=2,
    ),
            ),
            (
                "clf",
                LogisticRegression(
                    class_weight="balanced",
                    max_iter=2000,
                    random_state=random_state,
                ),
            ),
        ]
    )
    X_train, X_test, y_train, y_test = train_test_split(
        X_text, y, test_size=0.2, random_state=random_state, stratify=y
    )
    pipe.fit(X_train, y_train)
    acc = float((pipe.predict(X_test) == y_test).mean())
    tfidf = pipe.named_steps["tfidf"]
    clf = pipe.named_steps["clf"]
    coef = clf.coef_[0]
    names = tfidf.get_feature_names_out()
    pairs = sorted(zip(names, coef), key=lambda x: -x[1])
    top = [
        (n, float(c))
        for n, c in pairs[:80]
        if c > 0 and len(n) >= 4 and not is_remap_api_fragment(n)
    ][:40]
    return top, {"holdout_accuracy": acc, "n_train": len(X_train), "n_test": len(X_test)}


def build_aws_byte_rule(
    statements: list[dict],
    name: str,
    priority: int,
    metric_name: str,
) -> dict:
    return {
        "Name": name,
        "Priority": priority,
        "Statement": {"OrStatement": {"Statements": statements}},
        "VisibilityConfig": {
            "SampledRequestsEnabled": True,
            "CloudWatchMetricsEnabled": True,
            "MetricName": metric_name,
        },
        "Action": {"Block": {}},
    }


def byte_match_statement(
    search_string: str,
    positional: str = "CONTAINS",
) -> dict:
    return {
        "ByteMatchStatement": {
            "SearchString": search_string,
            "FieldToMatch": {"AllQueryArguments": {}},
            "TextTransformations": [
                {"Priority": 1, "Type": "URL_DECODE"},
                {"Priority": 2, "Type": "LOWERCASE"},
            ],
            "PositionalConstraint": positional,
        }
    }


def _regex_string_byte_len(s: str) -> int:
    return len(s.encode("utf-8"))


def literals_to_regex_chunks(
    literals: list[str],
    max_regex_bytes: int,
) -> list[str]:
    chunks: list[list[str]] = []
    cur: list[str] = []
    cur_bytes = 0
    for raw in literals:
        part = re.escape(raw.strip())
        if not part:
            continue
        need = _regex_string_byte_len(part)
        sep = 1 if cur else 0
        if cur and cur_bytes + sep + need > max_regex_bytes:
            chunks.append(cur)
            cur = [part]
            cur_bytes = need
        else:
            if cur:
                cur_bytes += 1
            cur.append(part)
            cur_bytes += need
    if cur:
        chunks.append(cur)
    out = []
    for group in chunks:
        body = "|".join(group)
        out.append(f"(?:{body})")
    return out


def regex_match_statement(regex_string: str) -> dict:
    return {
        "RegexMatchStatement": {
            "RegexString": regex_string,
            "FieldToMatch": {"AllQueryArguments": {}},
            "TextTransformations": [
                {"Priority": 1, "Type": "URL_DECODE"},
                {"Priority": 2, "Type": "LOWERCASE"},
            ],
        }
    }


def build_compact_regex_rule(
    literals: list[str],
    name: str,
    priority: int,
    metric_name: str,
    max_regex_bytes: int,
) -> dict | None:
    chunks = literals_to_regex_chunks(literals, max_regex_bytes=max_regex_bytes)
    if not chunks:
        return None
    stmts = [regex_match_statement(rx) for rx in chunks]
    return build_aws_byte_rule(stmts, name=name, priority=priority, metric_name=metric_name)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Build AWS WAF rule suggestions from mutate_rules.json (general) and/or bypass/blocked JSONL (data-specific)."
    )
    ap.add_argument(
        "--mode",
        choices=("mutate", "data", "both"),
        default="both",
        help="mutate: patterns from mutate_rules only; data: mine JSONL + ML n-grams; both: mutate first then data.",
    )
    ap.add_argument(
        "--mutate-rules",
        type=Path,
        default=DEFAULT_MUTATE_RULES,
        help="Path to mutate_rules.json (same schema as adv_mutate / ml-waf-blocked-adv).",
    )
    ap.add_argument(
        "--mutate-regex-cap",
        type=int,
        default=120,
        help="Max regex patterns taken from mutate_rules (regex_rules + per-fn signatures).",
    )
    ap.add_argument(
        "--data-dirs",
        nargs="*",
        type=Path,
        default=DEFAULT_DATA_DIRS,
        help="Folders containing data/*.jsonl (default: ml-waf-aws-test/data and ml-waf/data)",
    )
    ap.add_argument("--out-json", type=Path, default=ROOT / "data" / "generated_aws_rule_suggestion.json")
    ap.add_argument("--out-report", type=Path, default=ROOT / "data" / "generated_rule_report.txt")
    ap.add_argument("--min-len", type=int, default=5)
    ap.add_argument("--max-len", type=int, default=40)
    ap.add_argument("--max-patterns", type=int, default=20)
    ap.add_argument(
        "--regex-pool",
        type=int,
        default=80,
        help="Max literals folded into compact RegexMatch alternation (often fewer WCU than many ByteMatch).",
    )
    ap.add_argument(
        "--max-regex-bytes",
        type=int,
        default=200,
        help="Max UTF-8 bytes per RegexString chunk before splitting (raise toward AWS limit if needed).",
    )
    ap.add_argument("--min-support", type=int, default=0, help="0 = auto from blocked count")
    ap.add_argument("--max-bypass-ratio", type=float, default=0.35)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument(
        "--bypass-generalize",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Mine bypass_learned (and related) payloads, strip id remap prefix, emit generalized regex patterns.",
    )
    ap.add_argument(
        "--bypass-regex-cap",
        type=int,
        default=48,
        help="Max regex patterns from bypass generalization.",
    )
    ap.add_argument(
        "--bypass-min-support-ratio",
        type=float,
        default=0.02,
        help="Substring must appear in at least this fraction of bypass payloads (after dedup).",
    )
    ap.add_argument(
        "--bypass-ngram-min-df",
        type=int,
        default=3,
        help="TF-IDF char n-gram min_df on bypass-only corpus.",
    )
    ap.add_argument(
        "--bypass-ngram-terms",
        type=int,
        default=18,
        help="Max char n-gram terms to add after generalization.",
    )
    ns = ap.parse_args()

    mutate_regexes: list[str] = []
    mutate_bytes: list[str] = []
    mutate_labels: list[str] = []
    mutate_rules_loaded: dict | None = None

    if ns.mode in ("mutate", "both"):
        mutate_rules_loaded = load_mutate_rules(ns.mutate_rules)
        if mutate_rules_loaded is None:
            if ns.mode == "mutate":
                print(
                    f"mutate mode requires a valid mutate_rules file: {ns.mutate_rules}",
                    file=sys.stderr,
                )
                return 2
            print(
                f"warning: mutate_rules not found ({ns.mutate_rules}); continuing with data branch only",
                file=sys.stderr,
            )
        else:
            mutate_regexes, mutate_bytes, mutate_labels = collect_patterns_from_mutate_rules(
                mutate_rules_loaded
            )
            mutate_regexes = mutate_regexes[: ns.mutate_regex_cap]

    bypass: list[str] = []
    blocked: list[str] = []
    benign: list[str] = []
    mined: list[tuple[str, float, int, int]] = []
    ngram_top: list[tuple[str, float]] = []
    ml_report: dict | None = None
    min_sup = 3

    if ns.mode in ("data", "both"):
        bypass, blocked, benign = collect_labeled_payloads(ns.data_dirs)
        min_sup = ns.min_support
        if min_sup <= 0:
            min_sup = max(3, int(0.02 * len(blocked)) + 1) if blocked else 3

        mined = mine_substrings(
            blocked,
            bypass,
            benign,
            min_len=ns.min_len,
            max_len=ns.max_len,
            min_support=min_sup,
            max_bypass_ratio=ns.max_bypass_ratio,
        )

        ngram_top, ml_report = train_linear_ngrams(
            bypass, blocked, max_features=60000, random_state=ns.seed
        )

    bypass_for_gen: list[str] = []
    if ns.bypass_generalize:
        bypass_for_gen = (
            bypass if ns.mode in ("data", "both") else collect_bypass_payloads(ns.data_dirs)
        )

    bypass_gen_regexes: list[str] = []
    bypass_gen_meta: dict = {}
    if ns.bypass_generalize and bypass_for_gen:
        bypass_gen_regexes, bypass_gen_meta = build_bypass_generalized_regexes(
            bypass_for_gen,
            min_support_ratio=ns.bypass_min_support_ratio,
            min_len=max(4, ns.min_len - 1),
            max_len=min(ns.max_len + 24, 72),
            max_patterns=ns.bypass_regex_cap,
            ngram_min_df=ns.bypass_ngram_min_df,
            ngram_max_terms=ns.bypass_ngram_terms,
        )
        bypass_gen_regexes = bypass_gen_regexes[: ns.bypass_regex_cap]

    seen_sub: set[str] = set()
    literal_pool: list[str] = []

    def push_literal(s: str) -> None:
        s = s.strip()
        if not s:
            return
        if is_remap_api_fragment(s):
            return
        if len(s.encode("utf-8")) > 50:
            s = s[:50]
        k = s.lower()
        if k in seen_sub:
            return
        seen_sub.add(k)
        literal_pool.append(s)

    for b in mutate_bytes:
        if len(literal_pool) >= ns.regex_pool:
            break
        push_literal(b)

    for sub, _score, _bc, _bh in mined:
        if len(literal_pool) >= ns.regex_pool:
            break
        push_literal(sub)

    for ngram, _coef in ngram_top:
        if len(literal_pool) >= ns.regex_pool:
            break
        if not re.match(r"^[ -~]{4,}$", ngram):
            continue
        if len(ngram.encode("utf-8")) > 50:
            continue
        push_literal(ngram)

    rule_regex_mutate = build_compact_regex_rule_raw(
        mutate_regexes,
        name="Generated-SQLi-From-MutateRules-Regex",
        priority=1,
        metric_name="GeneratedSqliFromMutateRegex",
        max_regex_bytes=ns.max_regex_bytes,
    )
    rx_mutate_chunks = raw_regex_to_chunks(
        mutate_regexes, max_regex_bytes=ns.max_regex_bytes
    )

    rule_regex_bypass_gen = build_compact_regex_rule_raw(
        bypass_gen_regexes,
        name="Generated-SQLi-BypassGeneralized-Regex",
        priority=1,
        metric_name="GeneratedSqliBypassGeneralized",
        max_regex_bytes=ns.max_regex_bytes,
    )
    rx_bypass_chunks = raw_regex_to_chunks(
        bypass_gen_regexes, max_regex_bytes=ns.max_regex_bytes
    )

    if not literal_pool and not mutate_regexes and not bypass_gen_regexes:
        print(
            "No patterns: use --mode mutate with a valid mutate_rules.json, or --mode data with JSONL data, enable --bypass-generalize with bypass JSONL, or fix filters (--min-support, --max-bypass-ratio).",
            file=sys.stderr,
        )
        return 2

    rule = None
    if literal_pool:
        stmts_byte = [byte_match_statement(s) for s in literal_pool[: ns.max_patterns]]
        rule = build_aws_byte_rule(
            stmts_byte,
            name="Generated-SQLi-Patterns-ByteMatch",
            priority=1,
            metric_name="GeneratedSqliByteMatch",
        )

    literals_for_regex = literal_pool[: ns.regex_pool]
    rx_chunks: list[str] = []
    rule_regex_data = None
    if literals_for_regex and ns.mode in ("data", "both"):
        rx_chunks = literals_to_regex_chunks(
            literals_for_regex, max_regex_bytes=ns.max_regex_bytes
        )
        rule_regex_data = build_compact_regex_rule(
            literals_for_regex,
            name="Generated-SQLi-From-Data-RegexCompact",
            priority=1,
            metric_name="GeneratedSqliFromDataRegex",
            max_regex_bytes=ns.max_regex_bytes,
        )

    out_payload = {
        "meta": {
            "mode": ns.mode,
            "mutate_rules_path": str(ns.mutate_rules),
            "mutate_rules_loaded": mutate_rules_loaded is not None,
            "mutate_regex_patterns": len(mutate_regexes),
            "mutate_byte_literals": len(mutate_bytes),
            "mutate_pattern_labels": [
                {"pattern": mutate_regexes[i], "label": mutate_labels[i]}
                for i in range(min(len(mutate_regexes), len(mutate_labels)))
            ],
            "sources": [str(p) for p in ns.data_dirs],
            "counts": {
                "bypass_unique": len(bypass),
                "blocked_unique": len(blocked),
                "benign_strings": len(benign),
            },
            "design_notes": {
                "mutate_rules": "regex_rules patterns and per-transform_fn signatures approximate what adv_mutate can emit; review AWS WAF regex compatibility.",
                "bypass_generalized": "Strips leading id remap prefix, adds structural regex (long 0x/x hex, %00), mines frequent substrings with doc support, generalizes literals to regex, adds TF-IDF char n-grams on normalized bypass-only text.",
                "why_byte_match": "ByteMatchStatement is easy to audit literal-by-literal but one statement per substring inflates Web ACL size/WCU.",
                "why_regex_compact_data": "RegexMatchStatement with re.escaped literals from the combined literal pool (mutate bytes + mined strings).",
                "why_regex_mutate": "RegexMatchStatement uses raw patterns from mutate_rules (regex_rules + fn map); preferred for broad coverage aligned with your mutator.",
                "remap_normalization": "Blocked/bypass strings are passed through normalize_for_mining_deep before substring mining and ML n-grams so windows do not start inside id remap tokens (e.g. Demo_project). Literals matching remap API fragments (e.g. roject%27) are dropped.",
                "caveat": "Review false positives; verify RegexString limits and RE2/PCRE subset for your Web ACL.",
            },
            "bypass_generalization": bypass_gen_meta,
            "bypass_generalized_regex_count": len(bypass_gen_regexes),
            "mine_params": {
                "min_support": min_sup,
                "min_len": ns.min_len,
                "max_len": ns.max_len,
                "max_bypass_ratio": ns.max_bypass_ratio,
                "max_byte_statements": ns.max_patterns,
                "regex_literals": len(literals_for_regex),
                "regex_chunks_data": len(rx_chunks),
                "regex_chunks_mutate": len(rx_mutate_chunks),
                "regex_chunks_bypass_generalized": len(rx_bypass_chunks),
                "max_regex_bytes_per_chunk": ns.max_regex_bytes,
            },
            "mined_substrings_top": [
                {"substring": s, "score": round(sc, 4), "blocked_windows": bc, "bypass_hits": bh}
                for s, sc, bc, bh in mined[:30]
            ],
            "linear_ngram_model": ml_report,
            "top_char_ngrams_positive_blocked": ngram_top[:25],
        },
        "rule": rule,
        "rule_regex_from_mutate_rules": rule_regex_mutate,
        "rule_regex_from_bypass_generalized": rule_regex_bypass_gen,
        "rule_regex_compact_from_data": rule_regex_data,
        "regex_strings_mutate_raw": rx_mutate_chunks,
        "regex_strings_bypass_generalized": rx_bypass_chunks,
        "regex_strings_data_only": rx_chunks,
        "rule_regex_compact": rule_regex_data,
        "regex_strings_only": rx_chunks,
    }

    ns.out_json.parent.mkdir(parents=True, exist_ok=True)
    with open(ns.out_json, "w", encoding="utf-8") as f:
        json.dump(out_payload, f, ensure_ascii=False, indent=2)

    n_rx_data = (
        len(rule_regex_data["Statement"]["OrStatement"]["Statements"])
        if rule_regex_data
        else 0
    )
    n_rx_mut = (
        len(rule_regex_mutate["Statement"]["OrStatement"]["Statements"])
        if rule_regex_mutate
        else 0
    )
    n_rx_bypass = (
        len(rule_regex_bypass_gen["Statement"]["OrStatement"]["Statements"])
        if rule_regex_bypass_gen
        else 0
    )
    n_byte = len(rule["Statement"]["OrStatement"]["Statements"]) if rule else 0
    lines = [
        f"mode={ns.mode} mutate_regex={len(mutate_regexes)} mutate_bytes={len(mutate_bytes)} bypass_gen_regex={len(bypass_gen_regexes)}",
        f"bypass_unique={len(bypass)} blocked_unique={len(blocked)} benign_strings={len(benign)}",
        f"min_support={min_sup} mined_candidates={len(mined)} byte_statements={n_byte} regex_mutate={n_rx_mut} regex_bypass_gen={n_rx_bypass} regex_data={n_rx_data} alt_chunks_mut={len(rx_mutate_chunks)} alt_chunks_bypass={len(rx_bypass_chunks)} alt_chunks_data={len(rx_chunks)}",
    ]
    if ml_report:
        lines.append(f"linear_holdout_acc={ml_report.get('holdout_accuracy')}")
    lines.append(f"wrote {ns.out_json}")
    ns.out_report.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
