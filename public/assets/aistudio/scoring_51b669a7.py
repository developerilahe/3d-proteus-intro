"""Explainable 0-100 scoring: technique baseline + similarity + lure + infra."""
from __future__ import annotations

from .confusables import skeleton
from .enrichment.models import DomainEnrichment, LookupStatus
from .lures import RISKY_TLDS, TYPO_TLDS, lures_in, tld_of
from .models import Candidate, DnsFacts, Finding, Signal
from .normalize import brand_in_subdomain_only, has_mixed_script, normalize, to_ascii
from .similarity import damerau_levenshtein

TECHNIQUE_CAP = 50
SIMILARITY_CAP = 25
LURE_CAP = 10
INFRA_CAP = 15

_MUTATION_LABELS: dict[str, str] = {
    "digit_for_letter": "Digit-for-letter substitution",
    "drop_char": "Character omission",
    "insert_char": "Character insertion",
    "double_char": "Character repetition",
    "swap_adjacent": "Adjacent character transposition",
    "insert_hyphen": "Hyphenation",
    "prepend_token": "Prefix token addition",
    "append_token": "Suffix token addition",
    "brand_plus_token": "Combosquatting (brand + token)",
    "token_plus_brand": "Combosquatting (token + brand)",
    "swap_tld": "TLD substitution",
    "single_char_swap": "Single-character homoglyph swap",
    "full_idn_label": "Full IDN label (Punycode)",
    "partial_idn_label": "Partial IDN label (Punycode)",
    "brand_as_subdomain": "Brand as subdomain of attacker parent",
    "drop_inner_letter": "Brand abbreviation",
    "first_plus_last_two": "Abbreviated brand (first + last two)",
    "initial_plus_keyword": "Initial + keyword abbreviation",
    "brand_plus_geo": "Brand + geography",
    "brand_geo_concat": "Brand + geography (concatenated)",
    "brand_plus_service": "Brand + service word",
    "typo_plus_keyword": "Typo + keyword combo",
    "transposed_plus_keyword": "Transposition + keyword combo",
    "unknown": "Unclassified mutation",
}


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


def compute_similarity_pct(brand_label: str, reg_label: str) -> int:
    if not reg_label:
        return 0
    if reg_label == brand_label:
        return 100
    brand_sk = skeleton(brand_label)
    reg_sk = skeleton(reg_label)
    if reg_sk == brand_sk and reg_label != brand_label:
        return 96
    if brand_sk and brand_sk in reg_sk:
        extra = max(0, len(reg_sk) - len(brand_sk))
        return max(65, 100 - 3 * extra)
    dist = damerau_levenshtein(brand_label, reg_label)
    ratio = 1.0 - dist / max(len(brand_label), len(reg_label))
    return max(0, min(100, round(ratio * 100)))


def _technique_signal(candidate: Candidate) -> Signal:
    base = min(TECHNIQUE_CAP, candidate.weight // 2)
    return _sig(
        "technique_baseline",
        f"Technique: {candidate.technique.replace('_', ' ').title()} ({candidate.importance})",
        base,
        f"Initial heuristic weight {candidate.weight}/100 — adjusted by context",
    )


def _similarity_signals(brand: str, candidate: Candidate) -> list[Signal]:
    out: list[Signal] = []
    brand_label = _brand_label(brand)
    brand_sk = skeleton(brand_label)
    reg = candidate.registrable.lower()
    reg_label = reg.split(".")[0]
    reg_label_sk = skeleton(reg_label)

    if brand_in_subdomain_only(brand_label, candidate.domain):
        out.append(_sig("brand_in_subdomain_only", "Brand only in subdomain", 15,
                        f"eTLD+1={candidate.registrable}"))
    elif reg_label_sk == brand_sk and reg_label != brand_label:
        out.append(_sig("homoglyph_clone", "Skeleton-identical clone", 15,
                        f"'{reg_label}' folds to '{reg_label_sk}'"))
    elif reg_label == brand_label and reg != normalize(brand):
        out.append(_sig("tld_swap_same_label", "Brand label reused on another TLD", 12,
                        f"eTLD+1={candidate.registrable}"))
    else:
        dist = damerau_levenshtein(brand_label, reg_label)
        if dist == 1:
            out.append(_sig("typosquat_distance_1", "Edit distance 1 from brand", 12))
        elif dist == 2:
            out.append(_sig("typosquat_distance_2", "Edit distance 2 from brand", 7))
        elif brand_label in reg:
            out.append(_sig("brand_in_registrable", "Brand embedded in registrable", 12,
                            f"'{brand_label}' in '{reg}'"))

    if has_mixed_script(reg):
        out.append(_sig("mixed_script", "Mixed-script label (Latin + Cyrillic/Greek)", 3))
    if any(lbl.startswith("xn--") for lbl in to_ascii(candidate.registrable).split(".")):
        out.append(_sig("punycode_label", "Punycode (xn--) label present", 2,
                        candidate.ascii_form or candidate.domain))
    return _cap(out, SIMILARITY_CAP)


def _lure_signals(candidate: Candidate) -> list[Signal]:
    out: list[Signal] = []
    lures = lures_in(candidate.registrable)
    if lures:
        out.append(_sig("lure_present", "Brand-lure token present", 6, ", ".join(lures)))
    if candidate.technique in ("brand_typo_keyword", "combosquatting"):
        out.append(_sig("technique_combo", "Combined typo + lure construction", 4))
    return _cap(out, LURE_CAP)


def _infra_signals(
    facts: DnsFacts | None, candidate: Candidate, enrichment: DomainEnrichment | None
) -> list[Signal]:
    out: list[Signal] = []
    if facts is not None:
        if facts.a_records or facts.aaaa_records:
            out.append(_sig("a_record", "Live DNS (A/AAAA)", 5,
                            ", ".join((*facts.a_records, *facts.aaaa_records)[:2])))
        if facts.mx_records:
            out.append(_sig("mx_present", "Mail-enabled (MX present)", 4,
                            ", ".join(facts.mx_records[:2])))
        if enrichment is None and not facts.spf:
            out.append(_sig("spf_absent", "SPF record absent or weak", 2))
        if enrichment is None and not facts.dmarc:
            out.append(_sig("dmarc_absent", "DMARC record absent", 2))
        if facts.created_days_ago is not None and facts.created_days_ago < 30:
            out.append(_sig("fresh_domain", f"Registered {facts.created_days_ago}d ago", 2))
    if enrichment is not None and facts and facts.is_live:
        if enrichment.dns.spf.status == LookupStatus.NO_RECORDS:
            out.append(_sig("spf_absent", "SPF record absent", 2))
        if enrichment.domain == enrichment.registrable and enrichment.dns.dmarc.status == LookupStatus.NO_RECORDS:
            out.append(_sig("dmarc_absent", "DMARC record absent", 2))
    tld = tld_of(candidate.registrable)
    if tld in RISKY_TLDS or tld in TYPO_TLDS:
        out.append(_sig("risky_tld", f"Risky/typo TLD .{tld}", 2))
    return _cap(out, INFRA_CAP)


def _tier(score: int, facts: DnsFacts | None, candidate: Candidate | None = None) -> str:
    live = bool(facts and facts.is_live)
    is_subdomain_impersonation = candidate and candidate.technique == "subdomain_impersonation"
    if live and score >= 75:
        return "CRITICAL"
    if live and is_subdomain_impersonation and score >= 60:
        return "CRITICAL"
    if live and score >= 55:
        return "HIGH"
    if score >= 35:
        return "WATCH"
    return "LOW"


def _mutation_type(candidate: Candidate) -> str:
    return _MUTATION_LABELS.get(candidate.rule, candidate.technique.replace("_", " ").title())


def analyze_candidate(
    brand: str,
    candidate: Candidate,
    facts: DnsFacts | None,
    allowlist: set[str] | frozenset[str] | None = None,
    *,
    enrichment: DomainEnrichment | None = None,
) -> Finding | None:
    if candidate.registrable.lower() == normalize(brand):
        return None
    if allowlist and candidate.registrable.lower() in {a.lower() for a in allowlist}:
        return None

    brand_label = _brand_label(brand)
    reg_label = candidate.registrable.lower().split(".")[0]
    similarity_pct = compute_similarity_pct(brand_label, reg_label)

    signals = tuple(
        [_technique_signal(candidate)]
        + _similarity_signals(brand, candidate)
        + _lure_signals(candidate)
        + _infra_signals(facts, candidate, enrichment)
    )

    total = sum(s.points for s in signals)
    if total > 100:
        total = 100
    if not signals:
        return None

    tier = _tier(total, facts, candidate)
    return Finding(
        brand=brand,
        candidate=candidate,
        facts=facts,
        signals=signals,
        tier=tier,
        similarity_pct=similarity_pct,
        mutation_type=_mutation_type(candidate),
    )


# Export the unified analytical assessment
from core.analysis import assess_domain  # noqa: E402
