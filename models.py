"""Shared data structures for ScamSense AI.

Every module imports its types from here so the data flowing between
scanner.py, threat_detection.py, official_domains.py, ai_explainer.py
and app.py stays consistent.
"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class RiskLevel(str, Enum):
    CONFIRMED_THREAT = "CONFIRMED THREAT"
    SUSPICIOUS = "SUSPICIOUS"
    INCONCLUSIVE = "INCONCLUSIVE"  # exactly three; never "SAFE"


class CheckStatus(str, Enum):
    COMPLETED = "completed"
    UNAVAILABLE = "unavailable"        # API down, timeout, missing key
    NOT_APPLICABLE = "not_applicable"  # e.g. no organisation claimed


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class ParsedURL:
    raw: str
    normalized: Optional[str]
    is_valid: bool
    error_key: Optional[str] = None     # "empty", "bad_scheme", "too_long", ...
    scheme: Optional[str] = None
    hostname: Optional[str] = None
    registered_domain: Optional[str] = None
    subdomain: Optional[str] = None
    subdomain_count: int = 0
    is_ip_address: bool = False
    has_userinfo: bool = False
    port: Optional[int] = None
    path: str = ""
    query: str = ""


@dataclass
class Indicator:
    code: str                 # e.g. "IP_AS_HOST" (see INDICATOR_CODES)
    severity: Severity
    evidence: str             # factual detail found in the URL
    title_key: str            # keys into messages.MESSAGES
    explanation_key: str
    params: dict = field(default_factory=dict)


INDICATOR_CODES = [
    "IP_AS_HOST", "EXCESS_SUBDOMAINS", "LOOKALIKE_DOMAIN", "URL_SHORTENER",
    "MISLEADING_HTTPS", "UNUSUAL_CHARS", "SUSPICIOUS_PATTERN", "REDIRECT_PATTERN",
]


@dataclass
class ThreatIntelResult:
    status: CheckStatus
    threat_found: bool = False          # True ONLY on a real API match
    threat_types: list = field(default_factory=list)
    source: str = "Google Safe Browsing"
    error_key: Optional[str] = None     # "no_api_key", "timeout", "http_error", "rate_limited"
    checked_at: Optional[str] = None


@dataclass
class OfficialOrg:
    name: str
    keywords: list
    official_domains: list
    category: str
    verification_source: str
    last_verified: str


@dataclass
class DomainComparison:
    status: CheckStatus
    claimed_org: Optional[str] = None
    submitted_domain: Optional[str] = None
    official_domains: list = field(default_factory=list)
    matches_official: Optional[bool] = None
    lookalike_of: Optional[str] = None
    similarity_note_key: Optional[str] = None
    verification_source: Optional[str] = None
    last_verified: Optional[str] = None


@dataclass
class EvidencePackage:
    """The ONLY data the AI model receives: facts from the scanner."""
    url: str
    risk_level: RiskLevel
    threat_intel: dict
    indicators: list          # dicts: code, severity, evidence
    domain_comparison: dict
    language: str             # "en" | "ta"


@dataclass
class AIExplanation:
    source: str               # "meta_ai" or "predefined"
    language: str
    summary: str
    why_flagged: list
    next_steps: list
    ai_available: bool
    error_key: Optional[str] = None


@dataclass
class ScanResult:
    parsed: ParsedURL
    risk_level: RiskLevel
    threat_intel: ThreatIntelResult
    indicators: list
    domain_comparison: DomainComparison
    explanation: AIExplanation
    recommended_actions: list
    incomplete_checks: list
    scanned_at: datetime
    disclaimer_key: str


def classify(threat: ThreatIntelResult, indicators: list,
             comparison: DomainComparison) -> RiskLevel:
    """Evidence-based classification. Never returns a 'safe' state."""
    if threat.status == CheckStatus.COMPLETED and threat.threat_found:
        return RiskLevel.CONFIRMED_THREAT
    if indicators or comparison.lookalike_of:
        return RiskLevel.SUSPICIOUS
    return RiskLevel.INCONCLUSIVE
