from __future__ import annotations

import math
from typing import Any


def wilson_ci(successes: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n <= 0:
        return (0.0, 0.0)
    phat = successes / n
    z2 = z * z
    denom = 1 + z2 / n
    center = phat + z2 / (2 * n)
    inner = z * math.sqrt(phat * (1 - phat) / n + z2 / (4 * n * n))
    low = (center - inner) / denom
    high = (center + inner) / denom
    return (max(0.0, low), min(1.0, high))


def _rankdata(a: list[float]) -> list[float]:
    n = len(a)
    order = sorted(range(n), key=lambda i: a[i])
    ranks = [0.0] * n
    i = 0
    while i < n:
        j = i
        while j + 1 < n and a[order[j + 1]] == a[order[i]]:
            j += 1
        avg_rank = (i + 1 + j + 1) / 2.0
        for k in range(i, j + 1):
            ranks[order[k]] = avg_rank
        i = j + 1
    return ranks


def spearman_rho(xs: list[float], ys: list[float]) -> float | None:
    n = len(xs)
    if n != len(ys) or n < 2:
        return None
    rx = _rankdata(xs)
    ry = _rankdata(ys)
    mean_x = sum(rx) / n
    mean_y = sum(ry) / n
    num = sum((rx[i] - mean_x) * (ry[i] - mean_y) for i in range(n))
    den_x = sum((rx[i] - mean_x) ** 2 for i in range(n))
    den_y = sum((ry[i] - mean_y) ** 2 for i in range(n))
    if den_x <= 0 or den_y <= 0:
        return None
    return num / math.sqrt(den_x * den_y)


def cross_env_spearman(
    rates_a: dict[str, float],
    rates_b: dict[str, float],
    n_a: dict[str, int] | None = None,
    n_b: dict[str, int] | None = None,
    min_attempts: int = 1,
) -> dict[str, Any]:
    keys = [k for k in rates_a if k in rates_b]
    if n_a is not None and n_b is not None:
        keys = [
            k
            for k in keys
            if n_a.get(k, 0) >= min_attempts and n_b.get(k, 0) >= min_attempts
        ]
    pairs = [(rates_a[k], rates_b[k]) for k in keys]
    if len(pairs) < 2:
        return {"n_variants": len(pairs), "spearman_rho": None, "variants_used": keys}
    xs = [p[0] for p in pairs]
    ys = [p[1] for p in pairs]
    rho = spearman_rho(xs, ys)
    return {"n_variants": len(pairs), "spearman_rho": rho, "variants_used": keys}
