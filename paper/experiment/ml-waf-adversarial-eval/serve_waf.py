import json
import os
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import joblib

_ML_WAF = Path(__file__).resolve().parent.parent / "ml-waf"
if str(_ML_WAF) not in sys.path:
    sys.path.insert(0, str(_ML_WAF))

from features import extract

from http_utils import payload_to_request


def _model_path() -> Path:
    return Path(os.environ.get("ML_WAF_MODEL", _ML_WAF / "models" / "waf_model.joblib"))


def _param_name() -> str:
    return os.environ.get("ML_WAF_QUERY_PARAM", "id")


def _port() -> int:
    return int(os.environ.get("ML_WAF_PORT", "8787"))


_model = None


def get_model():
    global _model
    if _model is None:
        p = _model_path()
        if not p.exists():
            raise FileNotFoundError(str(p))
        _model = joblib.load(p)["model"]
    return _model


def score_payload(payload: str) -> tuple[int, float]:
    m = get_model()
    req = payload_to_request(payload, _param_name())
    x = [extract(req)]
    pred = int(m.predict(x)[0])
    proba = m.predict_proba(x)[0]
    score = float(proba[1])
    return pred, score


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def _json(self, code: int, body: dict):
        raw = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        u = urlparse(self.path)
        if u.path in ("/", "/health"):
            self._json(200, {"ok": True, "service": "ml-waf-adversarial-eval"})
            return
        if u.path not in ("/waf", "/evaluate"):
            self._json(404, {"error": "not_found"})
            return
        qs = parse_qs(u.query)
        payload = (qs.get("payload") or qs.get("p") or [""])[0]
        if not payload:
            self._json(400, {"error": "missing_payload", "hint": "GET /waf?payload=..."})
            return
        try:
            pred, score = score_payload(payload)
            blocked = pred == 1
            self._json(
                200,
                {
                    "blocked": blocked,
                    "pred": pred,
                    "attack_score": score,
                    "label": "attack" if pred == 1 else "benign",
                },
            )
        except FileNotFoundError as e:
            self._json(500, {"error": "model_missing", "path": str(e)})

    def do_POST(self):
        u = urlparse(self.path)
        if u.path not in ("/waf", "/evaluate"):
            self._json(404, {"error": "not_found"})
            return
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b"{}"
        try:
            data = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            self._json(400, {"error": "invalid_json"})
            return
        payload = data.get("payload") or data.get("p") or ""
        if not isinstance(payload, str):
            payload = str(payload)
        if not payload:
            self._json(400, {"error": "missing_payload"})
            return
        try:
            pred, score = score_payload(payload)
            blocked = pred == 1
            self._json(
                200,
                {
                    "blocked": blocked,
                    "pred": pred,
                    "attack_score": score,
                    "label": "attack" if pred == 1 else "benign",
                },
            )
        except FileNotFoundError as e:
            self._json(500, {"error": "model_missing", "path": str(e)})


def main():
    port = _port()
    httpd = HTTPServer(("127.0.0.1", port), Handler)
    print(f"ML WAF listening http://127.0.0.1:{port}/waf?payload=...", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
