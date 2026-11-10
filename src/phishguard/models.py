"""Core data models shared by every PhishGuard analyzer.

The models are deliberately small and JSON-friendly so the Streamlit UI,
the future FastAPI service, and the test suite can all use the same result
shape.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Verdict(StrEnum):
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    LIKELY_SAFE = "likely_safe"
    UNKNOWN = "unknown"


SEVERITY_ORDER = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

VERDICT_LABELS = {
    Verdict.MALICIOUS: "Malicious",
    Verdict.SUSPICIOUS: "Suspicious",
    Verdict.LIKELY_SAFE: "Likely safe",
    Verdict.UNKNOWN: "Unknown",
}


@dataclass(frozen=True)
class Signal:
    """One explainable indicator found during an analysis."""

    id: str
    title: str
    severity: Severity
    category: str
    description: str
    evidence: str = ""
    weight: int = 0
    confidence: float = 1.0
    source: str = "heuristic"

    def __post_init__(self) -> None:
        object.__setattr__(self, "weight", max(0, min(100, int(self.weight))))
        object.__setattr__(self, "confidence", max(0.0, min(1.0, float(self.confidence))))

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "category": self.category,
            "description": self.description,
            "evidence": self.evidence,
            "weight": self.weight,
            "confidence": round(self.confidence, 2),
            "source": self.source,
        }


@dataclass
class AnalysisResult:
    """The common result returned by every analyzer."""

    analyzer: str
    target: str
    score: int = 0
    verdict: Verdict = Verdict.UNKNOWN
    summary: str = ""
    signals: list[Signal] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    recommendations: list[str] = field(default_factory=list)
    confidence: float = 0.0
    error: str | None = None

    def add(self, signal: Signal) -> None:
        self.signals.append(signal)

    def add_many(self, signals: list[Signal]) -> None:
        self.signals.extend(signals)

    def to_dict(self) -> dict[str, Any]:
        return {
            "analyzer": self.analyzer,
            "target": self.target,
            "score": self.score,
            "verdict": self.verdict.value,
            "verdict_label": VERDICT_LABELS[self.verdict],
            "summary": self.summary,
            "confidence": round(self.confidence, 2),
            "signals": [signal.to_dict() for signal in self.signals],
            "metadata": self.metadata,
            "recommendations": self.recommendations,
            "error": self.error,
        }

    def to_markdown(self) -> str:
        lines = [
            f"# PhishGuard report: {self.analyzer}",
            "",
            f"**Target:** `{self.target}`",
            f"**Verdict:** {VERDICT_LABELS[self.verdict]}",
            f"**Risk score:** {self.score}/100",
            f"**Confidence:** {round(self.confidence * 100)}%",
            "",
            self.summary,
            "",
            "## Signals",
            "",
        ]
        if not self.signals:
            lines.append("_No indicators were found._")
        else:
            lines.extend(
                [
                    "| Severity | Indicator | Evidence |",
                    "| --- | --- | --- |",
                ]
            )
            for signal in self.signals:
                evidence = signal.evidence.replace("|", "\\|")[:300]
                lines.append(
                    f"| {signal.severity.value} | {signal.title} | {evidence} |"
                )
        lines.extend(["", "## Recommended actions", ""])
        if self.recommendations:
            lines.extend(f"- {item}" for item in self.recommendations)
        else:
            lines.append("- Review the indicators above before taking action.")
        lines.extend(
            [
                "",
                "---",
                "PhishGuard findings are indicators for human review, not proof.",
            ]
        )
        return "\n".join(lines)


def sort_signals(signals: list[Signal]) -> list[Signal]:
    """Most severe and highest-weight signals first."""
    return sorted(
        signals,
        key=lambda signal: (SEVERITY_ORDER[signal.severity], signal.weight),
        reverse=True,
    )
