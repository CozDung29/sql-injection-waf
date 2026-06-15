from __future__ import annotations

import csv
import sys
from pathlib import Path
from typing import Any


def resolve_output_path(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    candidates = [path] + [
        path.with_name(f"{path.stem}_new{i}{path.suffix}") for i in range(1, 30)
    ]
    last: OSError | None = None
    for cand in candidates:
        try:
            with cand.open("w", encoding="utf-8", newline="") as f:
                f.write("")
            cand.unlink(missing_ok=True)
            if cand != path:
                print(
                    f"warn: could not write {path} (file open in another app?); "
                    f"wrote {cand.name} instead",
                    file=sys.stderr,
                )
            return cand
        except PermissionError as e:
            last = e
            continue
        except OSError as e:
            last = e
            continue
    raise PermissionError(path) from last


def write_variant_csv(rows: list[dict[str, Any]], path: Path, env_label: str) -> None:
    path = resolve_output_path(path)
    fieldnames = [
        "env",
        "variant",
        "attempts",
        "bypass",
        "blocked",
        "other",
        "bypass_rate",
        "ci95_low",
        "ci95_high",
    ]
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow(
                {
                    "env": env_label,
                    "variant": r.get("variant", ""),
                    "attempts": r.get("attempts", 0),
                    "bypass": r.get("bypass", 0),
                    "blocked": r.get("blocked", 0),
                    "other": r.get("other", 0),
                    "bypass_rate": f"{r.get('bypass_rate', 0):.6f}",
                    "ci95_low": f"{r.get('bypass_rate_ci95_low', 0):.6f}",
                    "ci95_high": f"{r.get('bypass_rate_ci95_high', 0):.6f}",
                }
            )


def write_latex_table(
    rows: list[dict[str, Any]],
    path: Path,
    caption: str,
    label: str,
    max_rows: int = 40,
) -> None:
    path = resolve_output_path(path)
    lines = [
        r"\begin{table}[t]",
        r"\centering",
        r"\small",
        f"\\caption{{{caption}}}",
        f"\\label{{{label}}}",
        r"\begin{tabular}{lrrrr}",
        r"\hline",
        r"Variant & $n$ & bypass & rate & 95\% CI \\",
        r"\hline",
    ]
    for r in rows[:max_rows]:
        v = str(r.get("variant", "")).replace("_", r"\_")[:48]
        n = int(r.get("attempts", 0))
        b = int(r.get("bypass", 0))
        rate = float(r.get("bypass_rate", 0))
        lo = float(r.get("bypass_rate_ci95_low", 0))
        hi = float(r.get("bypass_rate_ci95_high", 0))
        lines.append(
            f"{v} & {n} & {b} & {rate:.3f} & [{lo:.3f},{hi:.3f}] \\\\"
        )
    lines.extend(
        [
            r"\hline",
            r"\end{tabular}",
            r"\end{table}",
            "",
        ]
    )
    path.write_text("\n".join(lines), encoding="utf-8")


def write_family_csv(rows: list[dict[str, Any]], path: Path, env_label: str) -> None:
    path = resolve_output_path(path)
    fieldnames = [
        "env",
        "family",
        "distinct_variants",
        "attempts",
        "bypass",
        "blocked",
        "other",
        "bypass_rate",
        "ci95_low",
        "ci95_high",
    ]
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow(
                {
                    "env": env_label,
                    "family": r.get("family", ""),
                    "distinct_variants": r.get("distinct_variants", 0),
                    "attempts": r.get("attempts", 0),
                    "bypass": r.get("bypass", 0),
                    "blocked": r.get("blocked", 0),
                    "other": r.get("other", 0),
                    "bypass_rate": f"{r.get('bypass_rate', 0):.6f}",
                    "ci95_low": f"{r.get('bypass_rate_ci95_low', 0):.6f}",
                    "ci95_high": f"{r.get('bypass_rate_ci95_high', 0):.6f}",
                }
            )


def write_latex_family_table(
    rows: list[dict[str, Any]],
    path: Path,
    caption: str,
    label: str,
    max_rows: int = 25,
) -> None:
    path = resolve_output_path(path)
    lines = [
        r"\begin{table}[t]",
        r"\centering",
        r"\small",
        f"\\caption{{{caption}}}",
        f"\\label{{{label}}}",
        r"\begin{tabular}{lrrrrr}",
        r"\hline",
        r"Family & $v$ & $n$ & bypass & rate & 95\% CI \\",
        r"\hline",
    ]
    for r in rows[:max_rows]:
        name = str(r.get("family", "")).replace("_", r"\_")[:40]
        dv = int(r.get("distinct_variants", 0))
        n = int(r.get("attempts", 0))
        b = int(r.get("bypass", 0))
        rate = float(r.get("bypass_rate", 0))
        lo = float(r.get("bypass_rate_ci95_low", 0))
        hi = float(r.get("bypass_rate_ci95_high", 0))
        lines.append(
            f"{name} & {dv} & {n} & {b} & {rate:.3f} & [{lo:.3f},{hi:.3f}] \\\\"
        )
    lines.extend(
        [
            r"\hline",
            r"\end{tabular}",
            r"\end{table}",
            "",
        ]
    )
    path.write_text("\n".join(lines), encoding="utf-8")
