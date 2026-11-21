"""Domain normalization, IDNA/punycode, script detection, eTLD+1 extraction."""
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