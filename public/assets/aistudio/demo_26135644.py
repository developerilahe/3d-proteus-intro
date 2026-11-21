"""Manual demo: python demo.py"""
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
