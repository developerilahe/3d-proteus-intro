"""Lure lexicon, risky/typo TLD sets, and helpers."""
from __future__ import annotations

from .normalize import from_ascii, normalize, registrable_domain

LURE_WORDS: tuple[str, ...] = (
    "login", "signin", "verify", "secure", "account", "update",
    "support", "billing", "payment", "invoice", "auth", "portal",
    "confirm", "recovery", "wallet", "helpdesk", "unlock", "alert",
    "notice", "mail",
)

RISKY_TLDS: tuple[str, ...] = (
    "zip", "mov", "xyz", "top", "buzz", "click", "live", "icu",
    "cyou", "rest", "shop", "cam", "sbs", "cfd", "monster", "lol",
)

TYPO_TLDS: tuple[str, ...] = ("cm", "co", "om", "con", "comm", "net", "org", "info")


def lures_in(domain: str) -> list[str]:
    reg = from_ascii(registrable_domain(domain)).lower()
    return [w for w in LURE_WORDS if w in reg]


def has_hyphenated_lure(domain: str) -> bool:
    decoded = from_ascii(registrable_domain(domain)).lower()
    if "-" not in decoded:
        return False
    return any(f"-{w}" in decoded or f"{w}-" in decoded for w in LURE_WORDS)


def tld_of(domain: str) -> str:
    parts = normalize(domain).split(".")
    return parts[-1] if parts else ""