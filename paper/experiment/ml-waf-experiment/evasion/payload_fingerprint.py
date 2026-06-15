import hashlib
import re
from urllib.parse import unquote


def normalize_for_fingerprint(payload: str) -> str:
    try:
        x = unquote(payload)
    except Exception:
        x = payload
    x = x.lower().strip()
    x = re.sub(r"\s+", " ", x)
    return x


def payload_fingerprint(payload: str) -> str:
    n = normalize_for_fingerprint(payload)
    return hashlib.sha256(n.encode("utf-8", errors="replace")).hexdigest()
