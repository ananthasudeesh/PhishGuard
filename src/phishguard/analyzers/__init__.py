"""Analyzer implementations for each PhishGuard input type."""

from .email import analyze_eml
from .file import analyze_file_bytes
from .qr import analyze_qr
from .social import analyze_social
from .url import analyze_url

__all__ = [
    "analyze_eml",
    "analyze_file_bytes",
    "analyze_qr",
    "analyze_social",
    "analyze_url",
]
