"""PhishGuard defensive phishing-analysis engine."""

from .intel import IntelClient
from .models import AnalysisResult, Severity, Signal, Verdict
from .scoring import finalize

__all__ = [
    "AnalysisResult",
    "IntelClient",
    "Severity",
    "Signal",
    "Verdict",
    "finalize",
]

__version__ = "0.1.0"
