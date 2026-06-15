import math


def wilson_upper_bound(successes: int, n: int, z: float = 1.96) -> float:
    if n <= 0:
        return 1.0
    p = successes / n
    z2 = z * z
    denom = 1 + z2 / n
    centre = p + z2 / (2 * n)
    rad = z * math.sqrt((p * (1 - p) + z2 / (4 * n)) / n)
    return (centre + rad) / denom
