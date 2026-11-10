from phishguard.models import Severity, Signal, Verdict
from phishguard.scoring import finalize, score_signals, verdict_for


def signal(identifier: str, weight: int, severity: Severity = Severity.MEDIUM) -> Signal:
    return Signal(
        id=identifier,
        title=identifier,
        severity=severity,
        category="test",
        description="test",
        weight=weight,
    )


def test_score_is_capped_and_deduplicated():
    signals = [signal("a", 60), signal("a", 80), signal("b", 50)]
    assert score_signals(signals) == 100


def test_verdict_thresholds():
    assert verdict_for(0, []) is Verdict.UNKNOWN
    assert verdict_for(0, [signal("info", 0, Severity.INFO)]) is Verdict.LIKELY_SAFE
    assert verdict_for(35, [signal("medium", 35)]) is Verdict.SUSPICIOUS
    assert verdict_for(70, [signal("high", 70)]) is Verdict.MALICIOUS


def test_finalize_sets_summary_and_recommendations():
    result = finalize(
        type(
            "Result",
            (),
            {
                "signals": [signal("credentials", 40, Severity.HIGH)],
                "metadata": {"url": "https://example.com"},
                "summary": "",
                "recommendations": [],
                "error": None,
                "analyzer": "test",
                "target": "test",
                "score": 0,
                "verdict": Verdict.UNKNOWN,
                "confidence": 0.0,
            },
        )()
    )
    assert result.score == 40
    assert result.verdict is Verdict.SUSPICIOUS
    assert result.summary
    assert result.recommendations
