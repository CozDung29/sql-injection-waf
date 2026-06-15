from pathlib import Path

import joblib

from path_setup import ensure_ml_waf_imports
from http_utils import payload_to_request


class MlSurrogate:
    def __init__(self, model_path: Path | None = None):
        ensure_ml_waf_imports()
        from features import extract

        self._extract = extract
        root = Path(__file__).resolve().parent.parent / "ml-waf"
        self._path = model_path or (root / "models" / "waf_model.joblib")
        self._model = None

    def load(self) -> None:
        if not self._path.exists():
            raise FileNotFoundError(f"ML model not found: {self._path}")
        payload = joblib.load(self._path)
        self._model = payload["model"]

    def blocks(self, payload: str, param: str = "id") -> bool:
        if self._model is None:
            self.load()
        req = payload_to_request(payload, param)
        x = [self._extract(req)]
        pred = int(self._model.predict(x)[0])
        return pred == 1
