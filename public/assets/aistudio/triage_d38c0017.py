"""Group findings by tier with deterministic sorting."""
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


def triage_by_severity(assessments: Iterable[dict]) -> dict[str, list[dict]]:
    """Groups assessments or findings by severity (CRITICAL, HIGH, WATCH, LOW)."""
    grouped: dict[str, list[dict]] = {t: [] for t in TIER_ORDER}
    for item in assessments:
        sev = item.get("severity") or item.get("tier") or "LOW"
        if sev not in grouped:
            grouped[sev] = []
        grouped[sev].append(item)
    return grouped


def triage_high_confidence_threats(
    assessments: Iterable[dict],
    min_confidence: int = 60,
) -> list[dict]:
    """Filters findings that meet or exceed a confidence corroboration threshold."""
    return [
        a for a in assessments
        if a.get("confidence_score", 0) >= min_confidence
        and a.get("severity") in ("CRITICAL", "HIGH")
    ]
