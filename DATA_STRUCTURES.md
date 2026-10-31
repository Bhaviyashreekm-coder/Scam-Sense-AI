# ScamSense AI – Data Structures

| File | Owns |
|---|---|
| models.py | All dataclasses/enums + classify() |
| messages.py | English/Tamil text keyed by code |
| official_domains.json | Editable verified-domain reference list |

## Data flow
URL string -> ParsedURL -> (Indicators, ThreatIntelResult, DomainComparison)
-> classify() -> RiskLevel -> EvidencePackage -> AIExplanation -> ScanResult -> dashboard

## Rules
- Only three risk levels: CONFIRMED THREAT, SUSPICIOUS, INCONCLUSIVE. Never "SAFE".
- threat_found is True only when Google Safe Browsing actually returns a match.
- If an API fails, status = UNAVAILABLE and the failure is listed in incomplete_checks.
- The AI receives only an EvidencePackage and may not add findings.
- Keep Safe Browsing results, URL heuristics and AI text separate.
