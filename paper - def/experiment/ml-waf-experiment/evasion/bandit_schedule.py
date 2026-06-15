import math
import random
from typing import Callable


def _total_pulls(trans: dict) -> int:
    s = 0
    for v in trans.values():
        s += int(v.get("bypass", 0)) + int(v.get("block", 0))
    return max(s, 1)


def sort_variants(
    variants: list[tuple[str, str]],
    mode: str,
    trans: dict,
    name_to_key: Callable[[str], str],
) -> list[tuple[str, str]]:
    if mode == "rate":

        def score_rate(item):
            pl, name = item
            key = name_to_key(name)
            t = trans.get(key, {"bypass": 0, "block": 0})
            b, bl = t.get("bypass", 0), t.get("block", 0)
            if b + bl == 0:
                return 0.0
            return b / (b + bl)

        return sorted(variants, key=score_rate, reverse=True)

    if mode == "thompson":

        def score_thompson(item):
            pl, name = item
            key = name_to_key(name)
            t = trans.get(key, {"bypass": 0, "block": 0})
            a = 1 + int(t.get("bypass", 0))
            b = 1 + int(t.get("block", 0))
            return random.betavariate(a, b)

        return sorted(variants, key=score_thompson, reverse=True)

    if mode == "ucb":
        n_total = _total_pulls(trans)

        def score_ucb(item):
            pl, name = item
            key = name_to_key(name)
            t = trans.get(key, {"bypass": 0, "block": 0})
            b, bl = int(t.get("bypass", 0)), int(t.get("block", 0))
            n = b + bl
            if n == 0:
                return float("inf")
            mean = b / n
            return mean + math.sqrt(2 * math.log(n_total) / n)

        return sorted(variants, key=score_ucb, reverse=True)

    def score_rate(item):
        pl, name = item
        key = name_to_key(name)
        t = trans.get(key, {"bypass": 0, "block": 0})
        b, bl = t.get("bypass", 0), t.get("block", 0)
        if b + bl == 0:
            return 0.0
        return b / (b + bl)

    return sorted(variants, key=score_rate, reverse=True)
