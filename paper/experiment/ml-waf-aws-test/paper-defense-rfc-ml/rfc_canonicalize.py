from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import unquote_plus


def unquote_chain(s: str, max_passes: int = 8) -> str:
    t = s
    for _ in range(max_passes):
        u = unquote_plus(t)
        if u == t:
            break
        t = u
    return t


def request_to_probe_text(req: dict[str, Any]) -> str:
    path = str(req.get("path") or "")
    query = str(req.get("query") or "")
    body = str(req.get("body") or "")
    return f"{path} {query} {body}".strip()


def canonicalize_probe_text(s: str) -> str:
    return unquote_chain(s.strip())


def load_attack_benign_json(data_dir: Path) -> tuple[list[dict], list[dict]]:
    attack_p = data_dir / "attack.json"
    benign_p = data_dir / "benign.json"
    attack: list[dict] = []
    benign: list[dict] = []
    if attack_p.is_file():
        attack = json.loads(attack_p.read_text(encoding="utf-8"))
        if not isinstance(attack, list):
            attack = []
    if benign_p.is_file():
        benign = json.loads(benign_p.read_text(encoding="utf-8"))
        if not isinstance(benign, list):
            benign = []
    return attack, benign


def texts_from_requests(reqs: list[dict[str, Any]], canonical: bool) -> list[str]:
    out: list[str] = []
    for r in reqs:
        if not isinstance(r, dict):
            continue
        raw = request_to_probe_text(r)
        if not raw:
            continue
        out.append(canonicalize_probe_text(raw) if canonical else raw)
    return out
