"""Transparent, rule-based risk scoring.

The score is intentionally simple: every signal contributes
``weight * confidence`` points, capped at 100. This keeps the result
explainable to a non-technical user and easy to test.
"""

from __future__ import annotations

from .models import AnalysisResult, Severity, Signal, Verdict, sort_signals


def score_signals(signals: list[Signal]) -> int:
    if not signals:
        return 0
    # If the same indicator is added twice (for example from a nested URL
    # and from the parent email), keep only the strongest instance.
    best: dict[str, Signal] = {}
    for signal in signals:
        current = best.get(signal.id)
        if current is None or signal.weight > current.weight:
            best[signal.id] = signal
    total = sum(signal.weight * signal.confidence for signal in best.values())
    return min(100, round(total))


def verdict_for(score: int, signals: list[Signal]) -> Verdict:
    critical = any(signal.severity is Severity.CRITICAL for signal in signals)
    if score >= 70 or (critical and score >= 50):
        return Verdict.MALICIOUS
    if score >= 35:
        return Verdict.SUSPICIOUS
    if signals and score < 35:
        return Verdict.LIKELY_SAFE
    return Verdict.UNKNOWN


def confidence_for(signals: list[Signal], metadata: dict | None = None) -> float:
    """A rough confidence estimate, not a statistical probability."""
    if not signals:
        return 0.25
    categories = {signal.category for signal in signals}
    data_points = len(metadata or {})
    value = 0.40 + min(0.25, len(signals) * 0.03) + min(0.20, len(categories) * 0.05)
    value += min(0.10, data_points * 0.01)
    return round(min(0.95, value), 2)


def default_recommendations(result: AnalysisResult) -> list[str]:
    categories = {signal.category for signal in result.signals}
    recommendations: list[str] = []

    if result.verdict is Verdict.MALICIOUS:
        recommendations.append("Do not click links, open attachments, or reply to this message.")
        recommendations.append("Report it to your email provider or security team and delete it.")
    elif result.verdict is Verdict.SUSPICIOUS:
        recommendations.append("Treat this as untrusted until you verify it through an official channel.")
        recommendations.append("Open the organisation's website or app directly instead of using the supplied link.")
    else:
        recommendations.append("No strong indicators were found, but stay cautious with unexpected messages.")

    if "credentials" in categories:
        recommendations.append("Never enter passwords, OTPs, card numbers, or identity documents from a link.")
    if "url" in categories:
        recommendations.append("Check the registered domain carefully; the part before the first single slash is what matters.")
    if "attachment" in categories:
        recommendations.append("Do not enable macros or run files from an unexpected sender.")
    if "qr" in categories:
        recommendations.append("Preview the decoded destination and confirm the domain before opening it.")
    if "social" in categories:
        recommendations.append("Verify the account through the platform's official profile or support page.")
    if "intel" in categories:
        recommendations.append("Threat-intelligence matches are strong signals, but confirm them with a second source.")

    # Keep the list short and actionable.
    deduped: list[str] = []
    for item in recommendations:
        if item not in deduped:
            deduped.append(item)
    return deduped[:5]


def finalize(result: AnalysisResult) -> AnalysisResult:
    result.signals = sort_signals(result.signals)
    result.score = score_signals(result.signals)
    result.verdict = verdict_for(result.score, result.signals)
    result.confidence = confidence_for(result.signals, result.metadata)
    if not result.summary:
        result.summary = _summary(result)
    if not result.recommendations:
        result.recommendations = default_recommendations(result)
    return result


def _summary(result: AnalysisResult) -> str:
    if result.error:
        return f"Analysis could not be completed: {result.error}"
    if not result.signals:
        return "No indicators were found in the data that was checked."
    high = sum(
        1
        for signal in result.signals
        if signal.severity in (Severity.HIGH, Severity.CRITICAL)
    )
    return (
        f"{len(result.signals)} indicator(s) found, including {high} high-severity "
        f"indicator(s). Review the evidence before acting."
    )
