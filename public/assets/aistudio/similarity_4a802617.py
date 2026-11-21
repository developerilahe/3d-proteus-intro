"""Damerau-Levenshtein and normalized similarity helpers."""
from __future__ import annotations


def damerau_levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    la, lb = len(a), len(b)
    if la == 0:
        return lb
    if lb == 0:
        return la
    d_prev2 = [0] * (lb + 1)
    d_prev = list(range(lb + 1))
    for i in range(1, la + 1):
        d_cur = [i] + [0] * lb
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d_cur[j] = min(
                d_cur[j - 1] + 1,
                d_prev[j] + 1,
                d_prev[j - 1] + cost,
            )
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d_cur[j] = min(d_cur[j], d_prev2[j - 2] + 1)
        d_prev2 = d_prev
        d_prev = d_cur
    return d_prev[lb]


def similarity_ratio(a: str, b: str) -> float:
    if not a and not b:
        return 1.0
    dist = damerau_levenshtein(a, b)
    return 1.0 - dist / max(len(a), len(b))