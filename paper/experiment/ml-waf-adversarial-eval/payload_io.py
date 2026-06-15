import json
from pathlib import Path
from typing import Any, Iterator


def extract_payload_and_group(row: dict[str, Any]) -> tuple[str, str | None]:
    pl = (
        row.get("variant_payload")
        or row.get("transformed")
        or row.get("payload")
        or ""
    )
    if not isinstance(pl, str):
        pl = str(pl)
    g = (
        row.get("adv_label")
        or row.get("transform")
        or row.get("name")
        or row.get("blocked_source_name")
    )
    if g is not None and not isinstance(g, str):
        g = str(g)
    return pl, g


def iter_payloads_from_path(path: Path) -> Iterator[tuple[str, str | None]]:
    path = path.resolve()
    if not path.exists():
        raise FileNotFoundError(str(path))
    if path.suffix.lower() == ".jsonl":
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                row = json.loads(line)
                pl, g = extract_payload_and_group(row)
                if pl:
                    yield pl, g
        return
    if path.suffix.lower() == ".json":
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            for row in data:
                if not isinstance(row, dict):
                    continue
                pl, g = extract_payload_and_group(row)
                if pl:
                    yield pl, g
        elif isinstance(data, dict):
            pl, g = extract_payload_and_group(data)
            if pl:
                yield pl, g
        return
    raise ValueError(f"Unsupported file type: {path}")


def load_all(paths: list[Path]) -> list[tuple[str, str | None]]:
    out: list[tuple[str, str | None]] = []
    for p in paths:
        out.extend(iter_payloads_from_path(p))
    return out
