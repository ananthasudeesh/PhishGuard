"""Social-media message and profile-text analyzer.

This is a language and link triage tool, not a platform API integration.
It does not scrape private accounts or bypass login walls.
"""

from __future__ import annotations

import re

from ..intel import IntelClient
from ..models import AnalysisResult, Severity, Signal
from ..scoring import finalize
from ..utils import extract_urls, safe_truncate
from .url import analyze_url

_PATTERN_GROUPS: list[tuple[str, str, Severity, int, list[str]]] = [
    (
        "social.crypto",
        "Crypto or investment promotion",
        Severity.MEDIUM,
        15,
        [
            "bitcoin", "btc", "ethereum", "usdt", "crypto", "forex",
            "trading bot", "guaranteed profit", "double your", "investment plan",
            "passive income", "mining", "airdrop", "presale",
        ],
    ),
    (
        "social.prize",
        "Prize, lottery, or giveaway language",
        Severity.MEDIUM,
        15,
        [
            "winner", "won", "prize", "lottery", "giveaway", "claim now",
            "free gift", "reward", "congratulations", "selected", "lucky",
        ],
    ),
    (
        "social.urgency",
        "Urgency or account-threat language",
        Severity.MEDIUM,
        12,
        [
            "urgent", "immediately", "act now", "final warning", "last chance",
            "within 24 hours", "within 48 hours", "account suspended",
            "verify now", "expires today", "will be deleted", "legal action",
        ],
    ),
    (
        "social.credentials",
        "Request for credentials or identity data",
        Severity.HIGH,
        22,
        [
            "password", "otp", "one-time code", "verify your account", "login",
            "sign in", "bank details", "card number", "aadhaar", "ssn",
            "seed phrase", "recovery phrase", "cvv", "pin code",
        ],
    ),
    (
        "social.impersonation",
        "Official-support impersonation language",
        Severity.MEDIUM,
        12,
        [
            "official", "support team", "customer care", "admin", "security team",
            "help desk", "account team", "verified agent",
        ],
    ),
    (
        "social.offplatform",
        "Pushes the conversation off-platform",
        Severity.MEDIUM,
        12,
        [
            "whatsapp", "telegram", "dm me", "direct message", "contact me on",
            "text me", "signal app", "google chat",
        ],
    ),
    (
        "social.job",
        "Suspicious work-from-home or easy-money offer",
        Severity.MEDIUM,
        12,
        [
            "work from home", "part-time job", "daily income", "no experience",
            "earn money", "easy money", "data entry job", "typing job",
        ],
    ),
    (
        "social.too_good",
        "Too-good-to-be-true promise",
        Severity.LOW,
        8,
        [
            "guaranteed", "risk-free", "100%", "free money", "instant profit",
            "no risk", "double your money",
        ],
    ),
]


def analyze_social(
    text: str,
    platform: str = "",
    *,
    use_intel: bool = False,
    online: bool = True,
    intel: IntelClient | None = None,
    max_urls: int = 3,
) -> AnalysisResult:
    target = (text or "").strip()
    result = AnalysisResult(analyzer="Social Media", target=safe_truncate(target, 120) or "empty text")
    if not target:
        result.error = "No message text supplied"
        return finalize(result)
    if len(target) > 50_000:
        target = target[:50_000]

    result.metadata.update(
        {
            "platform": platform or "unspecified",
            "text_length": len(target),
            "hashtags": sorted(set(re.findall(r"#\w+", target)))[:20],
            "mentions": sorted(set(re.findall(r"@\w+", target)))[:20],
        }
    )

    result.add(
        Signal(
            id="social.analyzed",
            title="Message text analysed",
            severity=Severity.INFO,
            category="social",
            description="Language patterns and shared links were checked locally.",
            evidence=f"{len(target)} characters",
            weight=0,
        )
    )

    for signal_id, title, severity, weight, terms in _PATTERN_GROUPS:
        hits = _match_terms(target, terms)
        if hits:
            result.add(
                Signal(
                    id=signal_id,
                    title=title,
                    severity=severity,
                    category="social",
                    description="The message contains language commonly used in social-engineering scams.",
                    evidence=", ".join(hits[:8]),
                    weight=weight,
                )
            )

    # Brand + "official/support" is a stronger impersonation signal.
    brand_hits = _brand_mentions(target)
    if brand_hits and _match_terms(target, ["official", "support", "customer care", "security team"]):
        result.add(
            Signal(
                id="social.brand_impersonation",
                title="Brand support impersonation",
                severity=Severity.HIGH,
                category="social",
                description="The message claims to be official support for a known brand.",
                evidence=", ".join(brand_hits[:5]),
                weight=22,
            )
        )

    urls = extract_urls(target)
    result.metadata["url_count"] = len(urls)
    url_reports = []
    for index, url in enumerate(urls[:max_urls], start=1):
        report = analyze_url(url, use_intel=use_intel, online=online, intel=intel)
        url_reports.append(report.to_dict())
        if report.score > 0:
            result.add(
                Signal(
                    id=f"social.url_{index}",
                    title=f"Shared link #{index} has risk indicators",
                    severity=_severity_from_score(report.score),
                    category="url",
                    description="The shared URL has its own indicators; review the URL report.",
                    evidence=safe_truncate(url, 250),
                    weight=min(55, max(10, report.score // 2)),
                )
            )
            for signal in report.signals[:2]:
                if signal.weight >= 20:
                    result.add(
                        Signal(
                            id=f"social.url_{index}.{signal.id}",
                            title=f"Link #{index}: {signal.title}",
                            severity=signal.severity,
                            category="url",
                            description=signal.description,
                            evidence=safe_truncate(signal.evidence, 250),
                            weight=min(40, round(signal.weight * 0.5)),
                            source=signal.source,
                        )
                    )
    result.metadata["url_reports"] = url_reports

    result.recommendations = [
        "Verify the account through the platform's official profile or support page.",
        "Do not send money, gift cards, crypto, or identity documents to someone you met online.",
        "Move the conversation to an official app or phone number you found independently.",
        "Report the account or post to the platform.",
    ]
    return finalize(result)


def _match_terms(text: str, terms: list[str]) -> list[str]:
    lowered = text.lower()
    hits: list[str] = []
    for term in terms:
        pattern = r"(?<![a-z0-9])" + re.escape(term.lower()) + r"(?![a-z0-9])"
        if re.search(pattern, lowered):
            hits.append(term)
    return hits


def _brand_mentions(text: str) -> list[str]:
    from ..utils import BRANDS

    lowered = text.lower()
    return sorted({brand for brand in BRANDS if len(brand) >= 4 and brand in lowered})


def _severity_from_score(score: int) -> Severity:
    if score >= 70:
        return Severity.CRITICAL
    if score >= 50:
        return Severity.HIGH
    if score >= 30:
        return Severity.MEDIUM
    if score > 0:
        return Severity.LOW
    return Severity.INFO
