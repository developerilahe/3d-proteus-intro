"""Bootstrap: create the entire core engine tree. Run: python bootstrap.py"""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).parent
FILES: dict[str, str] = {}

FILES["core/__init__.py"] = r'''"""Offline Lookalike Domain & Brand Abuse Detection Engine."""
'''

FILES["core/models.py"] = r'''"""Immutable data contracts for the detection engine."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping, Protocol


TIER_ORDER: Mapping[str, int] = {
    "CRITICAL": 0,
    "HIGH": 1,
    "WATCH": 2,
    "LOW": 3,
}


@dataclass(frozen=True)
class Candidate:
    domain: str
    ascii_form: str
    registrable: str
    family: str
    rule: str
    provenance: tuple[tuple[str, str], ...] = ()

    @property
    def provenance_dict(self) -> dict[str, str]:
        return dict(self.provenance)


@dataclass(frozen=True)
class Signal:
    key: str
    label: str
    points: int
    evidence: str = ""


@dataclass(frozen=True)
class DnsFacts:
    a_records: tuple[str, ...] = ()
    aaaa_records: tuple[str, ...] = ()
    mx_records: tuple[str, ...] = ()
    ns_records: tuple[str, ...] = ()
    spf: str | None = None
    dmarc: str | None = None
    created_days_ago: int | None = None
    registrar: str | None = None

    @property
    def is_live(self) -> bool:
        return bool(self.a_records or self.aaaa_records or self.mx_records)

    @property
    def is_mail_enabled(self) -> bool:
        return bool(self.mx_records)

    @classmethod
    def from_dict(cls, data: dict) -> "DnsFacts":
        return cls(
            a_records=tuple(data.get("a_records") or ()),
            aaaa_records=tuple(data.get("aaaa_records") or ()),
            mx_records=tuple(data.get("mx_records") or ()),
            ns_records=tuple(data.get("ns_records") or ()),
            spf=data.get("spf"),
            dmarc=data.get("dmarc"),
            created_days_ago=data.get("created_days_ago"),
            registrar=data.get("registrar"),
        )


@dataclass(frozen=True)
class Finding:
    brand: str
    candidate: Candidate
    facts: DnsFacts | None
    signals: tuple[Signal, ...]
    tier: str = "LOW"
    score: int = field(init=False, default=0)

    def __post_init__(self) -> None:
        total = sum(s.points for s in self.signals)
        if total < 0 or total > 100:
            raise ValueError(
                f"score {total} outside [0,100] for {self.candidate.registrable} "
                f"signals={[s.key for s in self.signals]}"
            )
        object.__setattr__(self, "score", total)


class Resolver(Protocol):
    def lookup(self, registrable: str) -> DnsFacts | None: ...
'''

FILES["core/normalize.py"] = r'''"""Domain normalization, IDNA/punycode, script detection, eTLD+1 extraction."""
from __future__ import annotations

import unicodedata
from pathlib import Path

MULTI_PART_SUFFIXES: frozenset[str] = frozenset({
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "net.uk", "ltd.uk", "plc.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "net.nz", "org.nz",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
    "co.in", "net.in", "org.in",
    "com.br", "net.br", "org.br",
    "co.za", "org.za", "net.za",
    "com.mx", "org.mx", "net.mx",
    "com.cn", "net.cn", "org.cn",
    "co.kr", "or.kr",
    "co.il", "org.il",
    "com.sg", "com.hk", "com.tw",
    "co.id", "or.id",
    "com.ar", "com.tr", "com.pl", "com.ua", "com.vn",
})

_SCRIPT_RANGES: tuple[tuple[int, int, str], ...] = (
    (0x0041, 0x005A, "latin"),
    (0x0061, 0x007A, "latin"),
    (0x00C0, 0x024F, "latin"),
    (0x0370, 0x03FF, "greek"),
    (0x0400, 0x04FF, "cyrillic"),
    (0x0500, 0x052F, "cyrillic"),
)


def _script_of(ch: str) -> str | None:
    cp = ord(ch)
    for lo, hi, script in _SCRIPT_RANGES:
        if lo <= cp <= hi:
            return script
    return None


def scripts_in(label: str) -> set[str]:
    out: set[str] = set()
    for ch in label:
        s = _script_of(ch)
        if s:
            out.add(s)
    return out


def has_mixed_script(label: str) -> bool:
    return len(scripts_in(label)) > 1


def normalize(domain: str) -> str:
    if not domain:
        return domain
    domain = domain.strip().rstrip(".").lower()
    return unicodedata.normalize("NFC", domain)


def to_ascii_label(label: str) -> str:
    if not label:
        return label
    if label.isascii():
        return label.lower()
    try:
        return "xn--" + label.encode("punycode").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):
        return label.lower()


def from_ascii_label(label: str) -> str:
    if not label:
        return label
    low = label.lower()
    if not low.startswith("xn--"):
        return low
    try:
        return low[4:].encode("ascii").decode("punycode")
    except (UnicodeError, UnicodeDecodeError):
        return low


def to_ascii(domain: str) -> str:
    domain = normalize(domain)
    if not domain:
        return domain
    return ".".join(to_ascii_label(l) for l in domain.split(".") if l)


def from_ascii(domain: str) -> str:
    domain = normalize(domain)
    if not domain:
        return domain
    return ".".join(from_ascii_label(l) for l in domain.split(".") if l)


def registrable_domain(domain: str) -> str:
    domain = normalize(domain)
    if not domain:
        return domain
    decoded = from_ascii(domain)
    labels = [l for l in decoded.split(".") if l]
    if len(labels) < 2:
        return decoded
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_PART_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def brand_in_subdomain_only(brand_label: str, domain: str) -> bool:
    brand = brand_label.split(".")[0].lower()
    decoded = from_ascii(normalize(domain))
    reg = registrable_domain(domain)
    if brand in reg.lower():
        return False
    reg_labels = set(reg.lower().split("."))
    sub_labels = [l.lower() for l in decoded.split(".") if l and l.lower() not in reg_labels]
    return any(brand in l for l in sub_labels)


def load_psl(path: str | Path | None = None) -> frozenset[str]:
    suffixes = set(MULTI_PART_SUFFIXES)
    if path:
        p = Path(path)
        if p.exists():
            with p.open(encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("//"):
                        continue
                    if line.startswith("!"):
                        suffixes.add(line[1:].lower())
                    elif "*." not in line:
                        suffixes.add(line.lower())
    return frozenset(suffixes)
'''

FILES["core/confusables.py"] = r'''"""Unicode confusables and the skeleton() visual-folding function."""
from __future__ import annotations

import unicodedata

from .normalize import from_ascii_label, normalize

CONFUSABLES: dict[str, str] = {
    "\u0430": "a", "\u0432": "b", "\u0435": "e", "\u0451": "e", "\u043a": "k", "\u043c": "m",
    "\u043d": "h", "\u043e": "o", "\u0440": "p", "\u0441": "c", "\u0442": "t", "\u0443": "y",
    "\u0445": "x", "\u0456": "i", "\u0458": "j", "\u0455": "s", "\u0501": "d", "\u0261": "g",
    "\u04bb": "h", "\u04cf": "l", "\u051b": "q", "\u051d": "w", "\u0475": "v", "\u044c": "b",
    "\u0410": "A", "\u0412": "B", "\u0415": "E", "\u041a": "K", "\u041c": "M", "\u041d": "H",
    "\u041e": "O", "\u0420": "P", "\u0421": "C", "\u0422": "T", "\u0423": "Y", "\u0425": "X",
    "\u0406": "I", "\u0408": "J", "\u0405": "S",
    "\u03b1": "a", "\u03b2": "b", "\u03b3": "y", "\u03b5": "e", "\u03b7": "n", "\u03b9": "i",
    "\u03ba": "k", "\u03bd": "v", "\u03bf": "o", "\u03c1": "p", "\u03c4": "t", "\u03c5": "u",
    "\u03c7": "x", "\u03b6": "z", "\u03bc": "u",
    "\u0391": "A", "\u0392": "B", "\u0395": "E", "\u0397": "H", "\u0399": "I", "\u039a": "K",
    "\u039d": "N", "\u039f": "O", "\u03a1": "P", "\u03a4": "T", "\u03a5": "Y", "\u03a7": "X",
    "\u0396": "Z",
    "\u00e0": "a", "\u00e1": "a", "\u00e2": "a", "\u00e3": "a", "\u00e4": "a", "\u00e5": "a",
    "\u0101": "a",
    "\u00e8": "e", "\u00e9": "e", "\u00ea": "e", "\u00eb": "e", "\u0113": "e",
    "\u00ec": "i", "\u00ed": "i", "\u00ee": "i", "\u00ef": "i", "\u012b": "i",
    "\u00f2": "o", "\u00f3": "o", "\u00f4": "o", "\u00f5": "o", "\u00f6": "o", "\u00f8": "o",
    "\u014d": "o",
    "\u00f9": "u", "\u00fa": "u", "\u00fb": "u", "\u00fc": "u", "\u016b": "u",
    "\u00f1": "n", "\u00e7": "c", "\u00fd": "y", "\u00ff": "y",
    "0": "o", "1": "l", "5": "s", "8": "b", "3": "e",
}

ASCII_MULTI: tuple[tuple[str, str], ...] = (
    ("rn", "m"),
    ("vv", "w"),
    ("cl", "d"),
    ("ii", "u"),
    ("l1", "ll"),
)


def skeleton(domain: str) -> str:
    domain = normalize(domain)
    if not domain:
        return domain
    out_labels = []
    for label in domain.split("."):
        if not label:
            continue
        out_labels.append(_skeleton_label(from_ascii_label(label)))
    return ".".join(out_labels)


def _skeleton_label(label: str) -> str:
    folded = "".join(CONFUSABLES.get(ch, ch) for ch in label)
    folded = unicodedata.normalize("NFKC", folded)
    for src, dst in ASCII_MULTI:
        folded = folded.replace(src, dst)
    return folded.lower()
'''

FILES["core/lures.py"] = r'''"""Lure lexicon, risky/typo TLD sets, and helpers."""
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
'''

FILES["core/similarity.py"] = r'''"""Damerau-Levenshtein and normalized similarity helpers."""
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
'''

FILES["core/permutations.py"] = r'''"""Deterministic permutation generators, each tagged with provenance."""
from __future__ import annotations

from .lures import LURE_WORDS, RISKY_TLDS, TYPO_TLDS
from .models import Candidate
from .normalize import normalize, registrable_domain, to_ascii

QWERTY_NEIGHBORS: dict[str, tuple[str, ...]] = {
    "q": ("w", "a"), "w": ("q", "e", "s"), "e": ("w", "r", "d"),
    "r": ("e", "t", "f"), "t": ("r", "y", "g"), "y": ("t", "u", "h"),
    "u": ("y", "i", "j"), "i": ("u", "o", "k"), "o": ("i", "p", "l"),
    "p": ("o",),
    "a": ("q", "s", "z"), "s": ("a", "d", "w", "x"), "d": ("s", "f", "e", "c"),
    "f": ("d", "g", "r", "v"), "g": ("f", "h", "t", "b"), "h": ("g", "j", "y", "n"),
    "j": ("h", "k", "u", "m"), "k": ("j", "l", "i"), "l": ("k", "o"),
    "z": ("a", "x"), "x": ("z", "c", "s"), "c": ("x", "v", "d"),
    "v": ("c", "b", "f"), "b": ("v", "n", "g"), "n": ("b", "m", "h"),
    "m": ("n", "j"),
}

HOMOGLYPHS: dict[str, tuple[str, ...]] = {
    "a": ("\u0430", "\u03b1", "\u00e0"),
    "b": ("\u044c", "6"),
    "c": ("\u0441", "\u03f2"),
    "d": ("\u0501",),
    "e": ("\u0435", "\u03b5", "\u00e9"),
    "g": ("\u0261",),
    "h": ("\u04bb",),
    "i": ("\u0456", "\u03b9", "1"),
    "j": ("\u0458",),
    "k": ("\u03ba",),
    "l": ("\u04cf", "1"),
    "m": ("\u043c", "rn"),
    "n": ("\u043f", "\u00f1"),
    "o": ("\u043e", "\u03bf", "0"),
    "p": ("\u0440", "\u03c1"),
    "q": ("\u051b",),
    "s": ("\u0455", "5"),
    "t": ("\u0442", "\u03c4"),
    "u": ("\u03c5", "\u00fc"),
    "v": ("\u03bd", "\u0475"),
    "w": ("\u051d", "vv"),
    "x": ("\u0445", "\u03c7"),
    "y": ("\u0443", "\u03b3"),
    "z": ("\u0396", "\u03b6"),
}

SUBDOMAIN_PARENTS: tuple[str, ...] = (
    "login-portal.xyz",
    "secure-auth.click",
    "verify-billing.top",
)


def _emit(domain: str, family: str, rule: str, **prov: str) -> Candidate:
    return Candidate(
        domain=domain,
        ascii_form=to_ascii(domain),
        registrable=registrable_domain(domain),
        family=family,
        rule=rule,
        provenance=tuple(sorted((k, str(v)) for k, v in prov.items())),
    )


def _base_brand(brand: str) -> tuple[str, str]:
    brand = normalize(brand)
    if "." in brand:
        head, _, tail = brand.partition(".")
        return head, tail
    return brand, "com"


def _join(label: str, tld: str) -> str:
    return f"{label}.{tld}"


def _typosquats(label: str, tld: str) -> list[Candidate]:
    out: list[Candidate] = []
    n = len(label)
    for i in range(n):
        out.append(_emit(_join(label[:i] + label[i + 1:], tld), "typosquat", "omission", index=str(i)))
    for i in range(n - 1):
        if label[i] == label[i + 1]:
            continue
        swapped = label[:i] + label[i + 1] + label[i] + label[i + 2:]
        out.append(_emit(_join(swapped, tld), "typosquat", "transposition", index=str(i)))
    for i in range(n):
        out.append(_emit(_join(label[:i + 1] + label[i] + label[i + 1:], tld), "typosquat", "duplication", index=str(i)))
    for i, ch in enumerate(label):
        for neighbor in QWERTY_NEIGHBORS.get(ch, ()):
            out.append(_emit(_join(label[:i] + neighbor + label[i + 1:], tld), "typosquat", "qwerty_sub", index=str(i), to=neighbor))
    for i in range(n + 1):
        for ch in "abcdefghijklmnopqrstuvwxyz":
            out.append(_emit(_join(label[:i] + ch + label[i:], tld), "typosquat", "insertion", index=str(i), to=ch))
    return out


def _homoglyphs(label: str, tld: str) -> list[Candidate]:
    out: list[Candidate] = []
    for i, ch in enumerate(label):
        for alt in HOMOGLYPHS.get(ch, ()):
            if alt == ch:
                continue
            out.append(_emit(
                _join(label[:i] + alt + label[i + 1:], tld),
                "homoglyph", "homoglyph_sub",
                index=str(i), from_char=ch, to=alt,
            ))
    return out


def _combosquats(label: str, tld: str) -> list[Candidate]:
    out: list[Candidate] = []
    for lure in LURE_WORDS:
        out.append(_emit(_join(f"{label}-{lure}", tld), "combosquat", "brand_lure", lure=lure))
        out.append(_emit(_join(f"{lure}-{label}", tld), "combosquat", "lure_brand", lure=lure))
        out.append(_emit(_join(f"{label}{lure}", tld), "combosquat", "brandlure", lure=lure))
        out.append(_emit(_join(f"{lure}{label}", tld), "combosquat", "lurebrand", lure=lure))
    return out


def _tld_variants(label: str, tld: str) -> list[Candidate]:
    out: list[Candidate] = []
    for alt in RISKY_TLDS:
        if alt == tld:
            continue
        out.append(_emit(_join(label, alt), "tld", "risky_tld", to=alt))
    for alt in TYPO_TLDS:
        if alt == tld:
            continue
        out.append(_emit(_join(label, alt), "tld", "typo_tld", to=alt))
    out.append(_emit(f"{label}{tld}.com", "tld", "dot_omission", omitted="."))
    for parent in SUBDOMAIN_PARENTS:
        out.append(_emit(f"{label}.{parent}", "tld", "subdomain_abuse"))
    return out


def generate(brand: str, max_candidates: int = 2000) -> list[Candidate]:
    label, tld = _base_brand(brand)
    seen: dict[str, Candidate] = {}
    for gen in (_homoglyphs, _typosquats, _combosquats, _tld_variants):
        for c in gen(label, tld):
            if c.ascii_form and c.ascii_form not in seen:
                seen[c.ascii_form] = c
            if len(seen) >= max_candidates:
                return list(seen.values())
    return list(seen.values())
'''

FILES["core/resolver.py"] = r'''"""Offline fixture resolver with a guarded opt-in hook for live lookups."""
from __future__ import annotations

import json
from pathlib import Path

from .models import DnsFacts, Resolver
from .normalize import from_ascii, to_ascii


class FixtureResolver:
    def __init__(self, fixture_path: str | Path):
        self.path = Path(fixture_path)
        self._data: dict[str, dict] = {}
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        with self.path.open(encoding="utf-8") as f:
            raw = json.load(f)
        if isinstance(raw, dict) and isinstance(raw.get("domains"), dict):
            raw = raw["domains"]
        self._data = {k.lower(): v for k, v in raw.items()}

    @staticmethod
    def _keys(registrable: str) -> set[str]:
        keys = {registrable.lower()}
        try:
            keys.add(to_ascii(registrable).lower())
        except Exception:
            pass
        try:
            keys.add(from_ascii(registrable).lower())
        except Exception:
            pass
        return keys

    def lookup(self, registrable: str) -> DnsFacts | None:
        for key in self._keys(registrable):
            if key in self._data:
                return DnsFacts.from_dict(self._data[key])
        return None


class NoopResolver:
    def lookup(self, registrable: str) -> DnsFacts | None:
        return None


def assert_offline_safe(resolver: Resolver) -> None:
    if isinstance(resolver, (FixtureResolver, NoopResolver)):
        return
    raise RuntimeError(
        f"Resolver {type(resolver).__name__} is not offline-safe. "
        "Live resolvers must be explicitly opted in and locally cached."
    )
'''

FILES["core/scoring.py"] = r'''"""Pure, deterministic 0-100 scoring with explainable Signal provenance."""
from __future__ import annotations

from .confusables import skeleton
from .lures import RISKY_TLDS, TYPO_TLDS, has_hyphenated_lure, lures_in, tld_of
from .models import Candidate, DnsFacts, Finding, Signal
from .normalize import brand_in_subdomain_only, has_mixed_script, normalize, to_ascii
from .similarity import damerau_levenshtein

SIMILARITY_CAP = 40
LURE_CAP = 20
INFRA_CAP = 40


def _sig(key: str, label: str, points: int, evidence: str = "") -> Signal:
    return Signal(key=key, label=label, points=points, evidence=evidence)


def _cap(signals: list[Signal], cap: int) -> list[Signal]:
    out: list[Signal] = []
    total = 0
    for s in signals:
        if total + s.points <= cap:
            out.append(s)
            total += s.points
    return out


def _brand_label(brand: str) -> str:
    return normalize(brand).split(".")[0]


def _similarity_signals(brand: str, candidate: Candidate) -> list[Signal]:
    out: list[Signal] = []
    brand_label = _brand_label(brand)
    brand_sk = skeleton(brand_label)
    reg = candidate.registrable.lower()
    reg_label = reg.split(".")[0]
    reg_label_sk = skeleton(reg_label)

    if brand_in_subdomain_only(brand_label, candidate.domain):
        out.append(_sig("brand_in_subdomain_only", "Brand appears only in subdomain, not eTLD+1", 20,
                        evidence=f"eTLD+1={candidate.registrable}"))
    elif reg_label_sk == brand_sk and reg_label != brand_label:
        out.append(_sig("homoglyph_clone", "Skeleton-identical clone (different codepoints)", 25,
                        evidence=f"'{reg_label}' folds to '{reg_label_sk}'"))
    elif reg_label == brand_label and reg != normalize(brand):
        out.append(_sig("tld_swap_same_label", "Brand label reused on different TLD", 20,
                        evidence=f"eTLD+1={candidate.registrable}"))
    else:
        dist = damerau_levenshtein(brand_label, reg_label)
        if dist == 1:
            out.append(_sig("typosquat_distance_1", "Edit distance 1 from brand", 20, evidence="distance=1"))
        elif dist == 2:
            out.append(_sig("typosquat_distance_2", "Edit distance 2 from brand", 12, evidence="distance=2"))
        elif brand_label in reg:
            out.append(_sig("brand_in_registrable", "Brand embedded inside registrable domain", 20,
                            evidence=f"'{brand_label}' in '{reg}'"))

    if has_mixed_script(reg):
        out.append(_sig("mixed_script", "Mixed-script label (Latin + Cyrillic/Greek)", 5,
                        evidence=f"scripts in '{reg}'"))
    if any(lbl.startswith("xn--") for lbl in to_ascii(candidate.registrable).split(".")):
        out.append(_sig("punycode_label", "Punycode (xn--) label present", 3,
                        evidence=candidate.ascii_form or candidate.domain))
    return _cap(out, SIMILARITY_CAP)


def _lure_signals(candidate: Candidate) -> list[Signal]:
    out: list[Signal] = []
    lures = lures_in(candidate.registrable)
    if lures:
        out.append(_sig("lure_present", "Brand-lure token present", 15, evidence=", ".join(lures)))
        for extra in lures[1:2]:
            out.append(_sig(f"lure_extra_{extra}", f"Additional lure '{extra}'", 3))
    if has_hyphenated_lure(candidate.registrable):
        out.append(_sig("hyphenated_lure", "Hyphenated lure construction", 2))
    return _cap(out, LURE_CAP)


def _infra_signals(facts: DnsFacts | None, candidate: Candidate) -> list[Signal]:
    out: list[Signal] = []
    if facts is not None:
        if facts.a_records or facts.aaaa_records:
            out.append(_sig("a_record", "Live DNS (A/AAAA present)", 10,
                            evidence=", ".join((*facts.a_records, *facts.aaaa_records)[:2])))
        if facts.mx_records:
            out.append(_sig("mx_present", "Mail-enabled (MX present)", 10,
                            evidence=", ".join(facts.mx_records[:2])))
        if not facts.spf:
            out.append(_sig("spf_absent", "SPF record absent or weak", 4))
        if not facts.dmarc:
            out.append(_sig("dmarc_absent", "DMARC record absent", 4))
        if facts.created_days_ago is not None:
            if facts.created_days_ago < 30:
                out.append(_sig("fresh_domain", f"Registered {facts.created_days_ago} days ago", 8))
            elif facts.created_days_ago < 90:
                out.append(_sig("recent_domain", f"Registered {facts.created_days_ago} days ago", 5))
    tld = tld_of(candidate.registrable)
    if tld in RISKY_TLDS or tld in TYPO_TLDS:
        out.append(_sig("risky_tld", f"Risky/typo TLD .{tld}", 4))
    return _cap(out, INFRA_CAP)


def _tier(score: int, facts: DnsFacts | None, brand: str, candidate: Candidate) -> str:
    live = bool(facts and facts.is_live)
    if score >= 75 and live:
        return "CRITICAL"
    if score >= 75:
        return "HIGH"
    if score >= 55 and live:
        return "HIGH"
    if score >= 35:
        return "WATCH"
    if facts is None and skeleton(candidate.registrable) == skeleton(_brand_label(brand)):
        return "WATCH"
    return "LOW"


def analyze_candidate(
    brand: str,
    candidate: Candidate,
    facts: DnsFacts | None,
    allowlist: set[str] | frozenset[str] | None = None,
) -> Finding | None:
    brand_norm = normalize(brand)
    if candidate.registrable.lower() == brand_norm:
        return None
    if allowlist and candidate.registrable.lower() in {a.lower() for a in allowlist}:
        return None

    signals = tuple(
        _similarity_signals(brand, candidate)
        + _lure_signals(candidate)
        + _infra_signals(facts, candidate)
    )
    if not signals:
        return None

    total = sum(s.points for s in signals)
    tier = _tier(total, facts, brand, candidate)
    return Finding(brand=brand, candidate=candidate, facts=facts, signals=signals, tier=tier)
'''

FILES["core/triage.py"] = r'''"""Group findings by tier with deterministic sorting."""
from __future__ import annotations

from collections import Counter
from typing import Iterable

from .models import Finding, TIER_ORDER


def sort_findings(findings: Iterable[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda f: (TIER_ORDER[f.tier], -f.score, f.candidate.registrable),
    )


def group_by_tier(findings: Iterable[Finding]) -> dict[str, list[Finding]]:
    grouped: dict[str, list[Finding]] = {t: [] for t in TIER_ORDER}
    for f in sort_findings(findings):
        grouped[f.tier].append(f)
    return grouped


def tier_counts(findings: Iterable[Finding]) -> dict[str, int]:
    counts = Counter(f.tier for f in findings)
    return {t: counts.get(t, 0) for t in TIER_ORDER}


def summarize(findings: Iterable[Finding]) -> dict:
    findings = list(findings)
    return {"total": len(findings), "by_tier": tier_counts(findings)}
'''

FILES["core/exporters.py"] = r'''"""Deterministic JSON/CSV exporters."""
from __future__ import annotations

import csv
import io
import json
from typing import Iterable

from .models import Finding
from .triage import sort_findings

CSV_COLUMNS = [
    "domain", "ascii_form", "registrable", "family", "rule",
    "tier", "score", "a_record", "mx", "spf", "dmarc",
    "age_days", "registrar", "reasons",
]


def _reasons(f: Finding) -> str:
    return " | ".join(f"{s.key}:{s.points}" for s in f.signals)


def _row(f: Finding) -> dict[str, str]:
    facts = f.facts
    return {
        "domain": f.candidate.domain,
        "ascii_form": f.candidate.ascii_form,
        "registrable": f.candidate.registrable,
        "family": f.candidate.family,
        "rule": f.candidate.rule,
        "tier": f.tier,
        "score": str(f.score),
        "a_record": "1" if facts and facts.a_records else "0",
        "mx": "1" if facts and facts.mx_records else "0",
        "spf": "1" if facts and facts.spf else "0",
        "dmarc": "1" if facts and facts.dmarc else "0",
        "age_days": str(facts.created_days_ago) if facts and facts.created_days_ago is not None else "",
        "registrar": (facts.registrar if facts and facts.registrar else ""),
        "reasons": _reasons(f),
    }


def export_csv(findings: Iterable[Finding]) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=CSV_COLUMNS)
    writer.writeheader()
    for f in sort_findings(findings):
        writer.writerow(_row(f))
    return buf.getvalue()


def export_json(findings: Iterable[Finding], brand: str | None = None) -> str:
    ordered = sort_findings(findings)
    payload = {
        "brand": brand,
        "count": len(ordered),
        "findings": [_finding_to_dict(f) for f in ordered],
    }
    return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False)


def _finding_to_dict(f: Finding) -> dict:
    return {
        "domain": f.candidate.domain,
        "ascii_form": f.candidate.ascii_form,
        "registrable": f.candidate.registrable,
        "family": f.candidate.family,
        "rule": f.candidate.rule,
        "provenance": dict(f.candidate.provenance),
        "tier": f.tier,
        "score": f.score,
        "facts": _facts_dict(f.facts),
        "signals": [
            {"key": s.key, "label": s.label, "points": s.points, "evidence": s.evidence}
            for s in f.signals
        ],
    }


def _facts_dict(facts) -> dict | None:
    if facts is None:
        return None
    return {
        "a_records": list(facts.a_records),
        "aaaa_records": list(facts.aaaa_records),
        "mx_records": list(facts.mx_records),
        "ns_records": list(facts.ns_records),
        "spf": facts.spf,
        "dmarc": facts.dmarc,
        "created_days_ago": facts.created_days_ago,
        "registrar": facts.registrar,
    }
'''

FILES["data/fixtures/dns_fixture.json"] = r'''{
  "domains": {
    "acmecorp.com": {
      "a_records": ["93.184.216.34"],
      "mx_records": ["10 mail.acmecorp.com"],
      "ns_records": ["ns1.acmecorp.com"],
      "spf": "v=spf1 include:_spf.acmecorp.com -all",
      "dmarc": "v=DMARC1; p=reject",
      "created_days_ago": 7200,
      "registrar": "corporate"
    },
    "acmecorp.net": {
      "a_records": ["93.184.216.35"],
      "spf": "v=spf1 -all",
      "dmarc": "v=DMARC1; p=reject",
      "created_days_ago": 7000,
      "registrar": "corporate"
    },
    "acmecorp-login.xyz": {
      "a_records": ["185.220.101.5"],
      "mx_records": ["10 mx.acmecorp-login.xyz"],
      "ns_records": ["ns1.cheap-host.xyz"],
      "spf": null,
      "dmarc": null,
      "created_days_ago": 6,
      "registrar": "cheapregistrar"
    },
    "\u0430cmecorp.com": {
      "a_records": ["45.142.213.11"],
      "mx_records": [],
      "spf": null,
      "dmarc": null,
      "created_days_ago": 45,
      "registrar": "privacy-protect"
    },
    "acmecorp.zip": {
      "a_records": ["104.21.23.44"],
      "mx_records": ["5 mail.acmecorp.zip"],
      "spf": null,
      "dmarc": null,
      "created_days_ago": 20,
      "registrar": "bulk-reg"
    },
    "acmecorp.co": {
      "a_records": ["104.21.23.55"],
      "spf": "v=spf1 -all",
      "dmarc": "v=DMARC1; p=none",
      "created_days_ago": 2000,
      "registrar": "colo"
    },
    "login-portal.xyz": {
      "a_records": ["185.199.108.99"],
      "mx_records": ["10 mail.login-portal.xyz"],
      "ns_records": ["ns1.cheap-host.xyz"],
      "spf": null,
      "dmarc": null,
      "created_days_ago": 3,
      "registrar": "cheapregistrar"
    },
    "secure-auth.click": {
      "a_records": ["45.9.148.12"],
      "mx_records": [],
      "spf": null,
      "dmarc": null,
      "created_days_ago": 15,
      "registrar": "cheapregistrar"
    }
  }
}
'''

FILES["conftest.py"] = r'''"""Ensures repo root is on sys.path so `import core` works under pytest."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
'''

FILES["tests/test_engine.py"] = r'''"""Regression tests for the offline detection engine."""
from __future__ import annotations

from pathlib import Path

import pytest

from core.confusables import skeleton
from core.exporters import export_csv, export_json
from core.models import Candidate, Finding, Signal
from core.normalize import (
    brand_in_subdomain_only,
    from_ascii,
    has_mixed_script,
    registrable_domain,
    to_ascii,
)
from core.permutations import generate
from core.resolver import FixtureResolver
from core.scoring import analyze_candidate
from core.similarity import damerau_levenshtein
from core.triage import sort_findings, tier_counts

FIXTURE = Path(__file__).parent.parent / "data" / "fixtures" / "dns_fixture.json"
BRAND = "acmecorp.com"
ALLOWLIST = {"acmecorp.com", "acmecorp.net"}


def test_skeleton_folds_cyrillic() -> None:
    assert skeleton("p\u0430ypal") == "paypal"
    assert skeleton("\u0430cmecorp") == "acmecorp"


def test_skeleton_multi_char_ascii() -> None:
    assert skeleton("rnicrosoft") == "microsoft"
    assert skeleton("vvindows") == "windows"
    assert skeleton("cloudflare") == "doudflare"


def test_skeleton_decodes_punycode() -> None:
    assert skeleton("xn--pypal-4ve.com") == "paypal.com"


def test_registrable_domain_multipart() -> None:
    assert registrable_domain("acme.co.uk") == "acme.co.uk"
    assert registrable_domain("shop.acme.co.uk") == "acme.co.uk"
    assert registrable_domain("a.b.acme.xyz") == "acme.xyz"
    assert registrable_domain("acmecorp.com") == "acmecorp.com"


def test_punycode_roundtrip() -> None:
    assert to_ascii("p\u0430ypal.com") == "xn--pypal-4ve.com"
    assert from_ascii("xn--pypal-4ve.com") == "p\u0430ypal.com"


def test_mixed_script_detection() -> None:
    assert has_mixed_script("\u0430cmecorp") is True
    assert has_mixed_script("acmecorp") is False


def test_brand_in_subdomain_only() -> None:
    assert brand_in_subdomain_only("acmecorp", "acmecorp.login-portal.xyz") is True
    assert brand_in_subdomain_only("acmecorp", "acmecorp.com") is False
    assert brand_in_subdomain_only("acmecorp", "shop.acmecorp.xyz") is False


def test_damerau_levenshtein_transposition() -> None:
    assert damerau_levenshtein("acmecorp", "acmeocrp") == 1
    assert damerau_levenshtein("acmecorp", "acmecorpx") == 1
    assert damerau_levenshtein("acmecorp", "acmecorp") == 0


def test_permutations_provenance_and_cap() -> None:
    candidates = generate(BRAND, max_candidates=500)
    assert len(candidates) <= 500
    assert all(c.provenance for c in candidates)
    domains_a = [c.domain for c in generate(BRAND, max_candidates=200)]
    domains_b = [c.domain for c in generate(BRAND, max_candidates=200)]
    assert domains_a == domains_b
    ascii_forms = [c.ascii_form for c in candidates]
    assert len(ascii_forms) == len(set(ascii_forms))


def _make_finding(signals: list[Signal]) -> Finding:
    cand = Candidate(
        domain="acmecorp-login.xyz",
        ascii_form="acmecorp-login.xyz",
        registrable="acmecorp-login.xyz",
        family="combosquat",
        rule="brand_lure",
    )
    return Finding(brand=BRAND, candidate=cand, facts=None, signals=tuple(signals), tier="LOW")


def test_score_equals_sum_of_signals() -> None:
    signals = [
        Signal("a", "A", 10),
        Signal("b", "B", 7),
        Signal("c", "C", 3),
    ]
    f = _make_finding(signals)
    assert f.score == 20
    assert f.score == sum(s.points for s in f.signals)


def test_score_out_of_range_raises() -> None:
    with pytest.raises(ValueError):
        _make_finding([Signal("x", "X", 200)])


def test_fixture_resolver_hits_unicode_key() -> None:
    resolver = FixtureResolver(FIXTURE)
    decoded = resolver.lookup("\u0430cmecorp.com")
    ascii_form = resolver.lookup("xn--cmecorp-1fg.com")
    assert decoded is not None and ascii_form is not None
    assert decoded.a_records == ascii_form.a_records


def test_allowlist_excludes_owned_domains() -> None:
    resolver = FixtureResolver(FIXTURE)
    candidates = generate(BRAND)
    owned = [c for c in candidates if c.registrable in ALLOWLIST]
    assert owned
    for c in owned:
        facts = resolver.lookup(c.registrable)
        assert analyze_candidate(BRAND, c, facts, allowlist=ALLOWLIST) is None


def _scan() -> list[Finding]:
    resolver = FixtureResolver(FIXTURE)
    findings = []
    for c in generate(BRAND, max_candidates=800):
        facts = resolver.lookup(c.registrable)
        f = analyze_candidate(BRAND, c, facts, allowlist=ALLOWLIST)
        if f is not None:
            findings.append(f)
    return findings


def test_end_to_end_has_critical_and_low() -> None:
    findings = _scan()
    counts = tier_counts(findings)
    assert counts["CRITICAL"] >= 1, counts
    assert counts["LOW"] >= 1, counts
    assert any(
        f.candidate.registrable == "acmecorp-login.xyz" and f.tier == "CRITICAL"
        for f in findings
    )


def test_end_to_end_deterministic_exports() -> None:
    findings = _scan()
    csv_1 = export_csv(findings)
    csv_2 = export_csv(findings)
    json_1 = export_json(findings, brand=BRAND)
    json_2 = export_json(findings, brand=BRAND)
    assert csv_1 == csv_2
    assert json_1 == json_2
    ordered = sort_findings(findings)
    assert ordered[0].tier == "CRITICAL"
    assert ordered[-1].tier == "LOW"


def test_export_csv_contains_reasons() -> None:
    findings = _scan()
    csv_text = export_csv(findings)
    header, first_row = csv_text.strip().split("\n", 1)
    assert "reasons" in header
    assert ":" in first_row
'''

FILES["requirements.txt"] = r'''pytest>=7.4
'''

FILES["demo.py"] = r'''"""Manual demo: python demo.py"""
from pathlib import Path

from core.exporters import export_csv, export_json
from core.permutations import generate
from core.resolver import FixtureResolver
from core.scoring import analyze_candidate
from core.triage import group_by_tier, tier_counts

BRAND = "acmecorp.com"
ALLOWLIST = {"acmecorp.com", "acmecorp.net"}
FIXTURE = Path(__file__).parent / "data" / "fixtures" / "dns_fixture.json"


def main() -> None:
    resolver = FixtureResolver(FIXTURE)
    candidates = generate(BRAND, max_candidates=1200)
    findings = []
    for c in candidates:
        facts = resolver.lookup(c.registrable)
        f = analyze_candidate(BRAND, c, facts, allowlist=ALLOWLIST)
        if f is not None:
            findings.append(f)

    print(f"Generated {len(candidates)} candidates, {len(findings)} scored")
    print(f"Tiers: {tier_counts(findings)}\n")

    for tier, group in group_by_tier(findings).items():
        print(f"-- {tier} ({len(group)}) --")
        for f in group[:5]:
            reasons = ", ".join(f"{s.key}={s.points}" for s in f.signals)
            print(f"  {f.candidate.registrable:35s} {f.score:>3}  [{reasons}]")
        print()

    out_csv = Path("findings.csv")
    out_json = Path("findings.json")
    out_csv.write_text(export_csv(findings), encoding="utf-8")
    out_json.write_text(export_json(findings, brand=BRAND), encoding="utf-8")
    print(f"Wrote {out_csv} and {out_json}")


if __name__ == "__main__":
    main()
'''


def main() -> None:
    written = 0
    for rel_path, content in FILES.items():
        target = ROOT / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        written += 1
    print(f"Wrote {written} files under {ROOT}")


if __name__ == "__main__":
    main()