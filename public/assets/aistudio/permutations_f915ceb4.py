"""Deterministic generation of all 17 impersonation techniques."""
from __future__ import annotations

from .lures import LURE_WORDS, RISKY_TLDS, TYPO_TLDS
from .models import Candidate
from .normalize import normalize, registrable_domain, to_ascii


TECHNIQUES: dict[str, dict] = {
    "character_substitution": {"importance": "High", "weight": 70, "family": "substitution"},
    "character_omission": {"importance": "Medium", "weight": 50, "family": "typo"},
    "character_insertion": {"importance": "Medium", "weight": 50, "family": "typo"},
    "character_repetition": {"importance": "Medium", "weight": 45, "family": "typo"},
    "character_transposition": {"importance": "Medium", "weight": 55, "family": "typo"},
    "hyphenation": {"importance": "Medium", "weight": 45, "family": "keyword"},
    "prefix_addition": {"importance": "High", "weight": 65, "family": "keyword"},
    "suffix_addition": {"importance": "High", "weight": 70, "family": "keyword"},
    "combosquatting": {"importance": "High", "weight": 75, "family": "keyword"},
    "tld_substitution": {"importance": "High", "weight": 70, "family": "tld"},
    "homoglyph": {"importance": "Very High", "weight": 90, "family": "homoglyph"},
    "idn_punycode": {"importance": "Very High", "weight": 90, "family": "homoglyph"},
    "subdomain_impersonation": {"importance": "High", "weight": 65, "family": "subdomain"},
    "brand_abbreviation": {"importance": "Medium", "weight": 45, "family": "keyword"},
    "brand_geography": {"importance": "Medium", "weight": 50, "family": "keyword"},
    "brand_service": {"importance": "High", "weight": 70, "family": "keyword"},
    "brand_typo_keyword": {"importance": "Very High", "weight": 90, "family": "hybrid"},
}

SUBSTITUTIONS: dict[str, tuple[str, ...]] = {
    "a": ("4",), "e": ("3",), "i": ("1",), "l": ("1",),
    "o": ("0",), "s": ("5",), "g": ("9",), "t": ("7",), "b": ("8",),
}

HOMOGLYPHS: dict[str, tuple[str, ...]] = {
    "a": ("\u0430", "\u03b1"), "b": ("\u044c",), "c": ("\u0441",),
    "d": ("\u0501",), "e": ("\u0435", "\u03b5"), "g": ("\u0261",),
    "h": ("\u04bb",), "i": ("\u0456", "\u03b9"), "j": ("\u0458",),
    "k": ("\u03ba",), "l": ("\u04cf", "\u217c"), "m": ("\u043c",),
    "n": ("\u043f",), "o": ("\u043e", "\u03bf"), "p": ("\u0440", "\u03c1"),
    "q": ("\u051b",), "s": ("\u0455",), "t": ("\u0442", "\u03c4"),
    "u": ("\u03c5",), "v": ("\u03bd",), "w": ("\u051d",),
    "x": ("\u0445",), "y": ("\u0443",), "z": ("\u03b6",),
}

PREFIX_TOKENS: tuple[str, ...] = (
    "secure-", "login-", "signin-", "verify-", "account-", "my-",
    "official-", "support-", "help-", "auth-",
)

SUFFIX_TOKENS: tuple[str, ...] = (
    "-login", "-signin", "-verify", "-secure", "-account",
    "-support", "-billing", "-help", "-portal", "-auth",
)

COMBO_TOKENS: tuple[str, ...] = (
    "security", "verification", "support", "billing", "payment",
    "login", "account", "wallet", "recovery", "portal", "help",
    "auth", "safe", "trust",
)

SERVICE_TOKENS: tuple[str, ...] = (
    "verification", "security", "support", "billing", "recovery",
    "onboarding", "compliance", "kyc",
)

GEOGRAPHY_TOKENS: tuple[str, ...] = (
    "azerbaijan", "turkey", "usa", "uk", "europe", "asia",
    "germany", "france", "uae", "india", "global",
)

SUBDOMAIN_PARENTS: tuple[str, ...] = (
    "login-portal.xyz",
    "secure-auth.click",
    "verify-billing.top",
    "account-verify.icu",
)


def _emit(domain: str, technique: str, rule: str, **prov: str) -> Candidate:
    meta = TECHNIQUES[technique]
    return Candidate(
        domain=domain,
        ascii_form=to_ascii(domain),
        registrable=registrable_domain(domain),
        family=meta["family"],
        rule=rule,
        technique=technique,
        importance=meta["importance"],
        weight=meta["weight"],
        provenance=tuple(sorted((k, str(v)) for k, v in prov.items())),
    )


def _base_brand(brand: str) -> tuple[str, str]:
    brand = normalize(brand)
    if "." in brand:
        parts = brand.split(".")
        label = parts[0]
        tld = ".".join(parts[1:])
        return label, tld
    return brand, "com"


def _join(label: str, tld: str) -> str:
    return f"{label}.{tld}"


def _gen_substitution(label: str, tld: str) -> list[Candidate]:
    out: list[Candidate] = []
    for i, ch in enumerate(label):
        for alt in SUBSTITUTIONS.get(ch, ()):
            out.append(_emit(
                _join(label[:i] + alt + label[i + 1:], tld),
                "character_substitution", "digit_for_letter",
                index=str(i), from_char=ch, to_char=alt,
            ))
    return out


def _gen_omission(label: str, tld: str) -> list[Candidate]:
    out: list[Candidate] = []
    for i in range(len(label)):
        out.append(_emit(
            _join(label[:i] + label[i + 1:], tld),
            "character_omission", "drop_char", index=str(i),
        ))
    return out


def _gen_insertion(label: str, tld: str) -> list[Candidate]:
    out: list[Candidate] = []
    insert_chars = "aeioulnrst"
    for i in range(len(label) + 1):
        for ch in insert_chars:
            out.append(_emit(
                _join(label[:i] + ch + label[i:], tld),
                "character_insertion", "insert_char",
                index=str(i), to_char=ch,
            ))
    return out


def _gen_repetition(label: str, tld: str) -> list[Candidate]:
    out: list[Candidate] = []
    for i in range(len(label)):
        out.append(_emit(
            _join(label[:i + 1] + label[i] + label[i + 1:], tld),
            "character_repetition", "double_char", index=str(i),
        ))
    return out


def _gen_transposition(label: str, tld: str) -> list[Candidate]:
    out: list[Candidate] = []
    for i in range(len(label) - 1):
        if label[i] == label[i + 1]:
            continue
        swapped = label[:i] + label[i + 1] + label[i] + label[i + 2:]
        out.append(_emit(
            _join(swapped, tld),
            "character_transposition", "swap_adjacent", index=str(i),
        ))
    return out


def _gen_hyphenation(label: str, tld: str) -> list[Candidate]:
    out: list[Candidate] = []
    for i in range(1, len(label)):
        out.append(_emit(
            _join(label[:i] + "-" + label[i:], tld),
            "hyphenation", "insert_hyphen", index=str(i),
        ))
    return out


def _gen_prefix(label: str, tld: str) -> list[Candidate]:
    out: list[Candidate] = []
    for tok in PREFIX_TOKENS:
        out.append(_emit(
            _join(tok + label, tld),
            "prefix_addition", "prepend_token", token=tok.strip("-"),
        ))
    return out


def _gen_suffix(label: str, tld: str) -> list[Candidate]:
    out: list[Candidate] = []
    for tok in SUFFIX_TOKENS:
        out.append(_emit(
            _join(label + tok, tld),
            "suffix_addition", "append_token", token=tok.strip("-"),
        ))
    return out


def _gen_combosquat(label: str, tld: str) -> list[Candidate]:
    out: list[Candidate] = []
    for tok in COMBO_TOKENS:
        out.append(_emit(
            _join(f"{label}{tok}", tld),
            "combosquatting", "brand_plus_token", token=tok,
        ))
        out.append(_emit(
            _join(f"{tok}{label}", tld),
            "combosquatting", "token_plus_brand", token=tok,
        ))
    return out


def _gen_tld_sub(label: str, tld: str) -> list[Candidate]:
    out: list[Candidate] = []
    all_tlds = set(RISKY_TLDS) | set(TYPO_TLDS) | {
        "com", "net", "org", "info", "biz", "io", "co", "tr", "az",
    }
    all_tlds.discard(tld)
    for alt in sorted(all_tlds):
        out.append(_emit(
            _join(label, alt),
            "tld_substitution", "swap_tld", to_tld=alt,
        ))
    return out


def _gen_homoglyph(label: str, tld: str) -> list[Candidate]:
    out: list[Candidate] = []
    for i, ch in enumerate(label):
        for alt in HOMOGLYPHS.get(ch, ()):
            out.append(_emit(
                _join(label[:i] + alt + label[i + 1:], tld),
                "homoglyph", "single_char_swap",
                index=str(i), from_char=ch, to_codepoint=f"U+{ord(alt):04X}",
            ))
    return out


def _gen_idn(label: str, tld: str) -> list[Candidate]:
    out: list[Candidate] = []
    idx = [i for i, ch in enumerate(label) if ch in HOMOGLYPHS]
    if len(idx) >= 2:
        new_label = list(label)
        for pos in idx:
            alts = HOMOGLYPHS.get(new_label[pos], ())
            if alts:
                new_label[pos] = alts[0]
        out.append(_emit(
            _join("".join(new_label), tld),
            "idn_punycode", "full_idn_label", swapped="multiple",
        ))
    if idx:
        new_label = list(label)
        for pos in idx:
            alts = HOMOGLYPHS.get(new_label[pos], ())
            if alts:
                new_label[pos] = alts[0]
        out.append(_emit(
            _join("".join(new_label), tld),
            "idn_punycode", "partial_idn_label", swapped=str(len(idx)),
        ))
    return out


def _gen_subdomain(label: str, tld: str) -> list[Candidate]:
    out: list[Candidate] = []
    for parent in SUBDOMAIN_PARENTS:
        out.append(_emit(
            f"{label}.{parent}",
            "subdomain_impersonation", "brand_as_subdomain", parent=parent,
        ))
    return out


def _gen_abbreviation(label: str, tld: str) -> list[Candidate]:
    out: list[Candidate] = []
    if len(label) < 4:
        return out
    first = label[0]
    rest = label[1:]
    if len(rest) >= 3:
        out.append(_emit(
            _join(first + rest[1:], tld),
            "brand_abbreviation", "drop_inner_letter",
            index="1",
        ))
    out.append(_emit(
        _join(first + rest[-2:], tld),
        "brand_abbreviation", "first_plus_last_two",
        index="last_two",
    ))
    for tok in ("login", "secure", "verify"):
        out.append(_emit(
            _join(f"{label[0]}{tok}", tld),
            "brand_abbreviation", "initial_plus_keyword", token=tok,
        ))
    return out


def _gen_geography(label: str, tld: str) -> list[Candidate]:
    out: list[Candidate] = []
    for geo in GEOGRAPHY_TOKENS:
        out.append(_emit(
            _join(f"{label}-{geo}", tld),
            "brand_geography", "brand_plus_geo", geo=geo,
        ))
        out.append(_emit(
            _join(f"{label}{geo}", tld),
            "brand_geography", "brand_geo_concat", geo=geo,
        ))
    return out


def _gen_service(label: str, tld: str) -> list[Candidate]:
    out: list[Candidate] = []
    for svc in SERVICE_TOKENS:
        out.append(_emit(
            _join(f"{label}-{svc}", tld),
            "brand_service", "brand_plus_service", service=svc,
        ))
    return out


def _gen_typo_keyword(label: str, tld: str) -> list[Candidate]:
    out: list[Candidate] = []
    for i, ch in enumerate(label):
        for alt in SUBSTITUTIONS.get(ch, ()):
            typo = label[:i] + alt + label[i + 1:]
            for kw in ("secure", "login", "verify"):
                out.append(_emit(
                    _join(f"{typo}-{kw}", tld),
                    "brand_typo_keyword", "typo_plus_keyword",
                    index=str(i), keyword=kw,
                ))
    if len(label) >= 3:
        for i in range(len(label) - 1):
            swapped = label[:i] + label[i + 1] + label[i] + label[i + 2:]
            for kw in ("secure", "verify"):
                out.append(_emit(
                    _join(f"{swapped}-{kw}", tld),
                    "brand_typo_keyword", "transposed_plus_keyword", keyword=kw,
                ))
    return out


# IMPORTANT ORDERING: repetition MUST run before insertion.
# If insertion runs first, it steals all repetition candidates
# (e.g. "exaamplebank" can be generated by either), leaving
# character_repetition with zero unique output.
# Insertion runs last because it produces the most candidates.
_GENERATORS = (
    _gen_substitution,
    _gen_omission,
    _gen_repetition,
    _gen_transposition,
    _gen_hyphenation,
    _gen_prefix,
    _gen_suffix,
    _gen_combosquat,
    _gen_tld_sub,
    _gen_homoglyph,
    _gen_idn,
    _gen_subdomain,
    _gen_abbreviation,
    _gen_geography,
    _gen_service,
    _gen_typo_keyword,
    _gen_insertion,
)


def generate(brand: str, max_candidates: int = 2000) -> list[Candidate]:
    label, tld = _base_brand(brand)
    seen: dict[str, Candidate] = {}
    for gen in _GENERATORS:
        for c in gen(label, tld):
            if c.ascii_form and c.ascii_form not in seen:
                seen[c.ascii_form] = c
            if len(seen) >= max_candidates:
                return list(seen.values())
    return list(seen.values())