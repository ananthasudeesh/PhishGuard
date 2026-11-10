"""QR-code analyzer: decode the image locally, then inspect the destination."""

from __future__ import annotations

from ..intel import IntelClient
from ..models import AnalysisResult, Severity, Signal
from ..scoring import finalize
from ..utils import (
    CREDENTIAL_WORDS,
    contains_any,
    is_http_url,
    safe_truncate,
)
from .url import analyze_url

try:
    import cv2
    import numpy as np
except Exception:  # pragma: no cover - optional dependency
    cv2 = None
    np = None


def decode_qr(data: bytes) -> list[str]:
    if cv2 is None or np is None or not data:
        return []
    try:
        image = cv2.imdecode(np.frombuffer(data, dtype=np.uint8), cv2.IMREAD_COLOR)
    except Exception:
        return []
    if image is None:
        return []

    detector = cv2.QRCodeDetector()
    try:
        ok, decoded, _points, _straight = detector.detectAndDecodeMulti(image)
        if ok:
            return [value.strip() for value in decoded if value and value.strip()]
    except Exception:
        pass
    try:
        value, _points, _straight = detector.detectAndDecode(image)
        return [value.strip()] if value and value.strip() else []
    except Exception:
        return []


def analyze_qr(
    data: bytes,
    filename: str = "qr.png",
    *,
    use_intel: bool = False,
    online: bool = True,
    intel: IntelClient | None = None,
    max_urls: int = 3,
) -> AnalysisResult:
    result = AnalysisResult(analyzer="QR Code", target=filename or "qr.png")
    if not data:
        result.error = "Empty image"
        return finalize(result)
    if len(data) > 10 * 1024 * 1024:
        result.error = "Image is larger than the 10 MB analysis limit"
        return finalize(result)

    decoded = decode_qr(data)
    result.metadata["decoded_count"] = len(decoded)
    result.metadata["decoded_values"] = [safe_truncate(value, 300) for value in decoded]
    if not decoded:
        result.error = "No QR code could be decoded from this image"
        return finalize(result)

    result.add(
        Signal(
            id="qr.decoded",
            title="QR code decoded locally",
            severity=Severity.INFO,
            category="qr",
            description="The image was decoded in memory; it was not uploaded to a third party.",
            evidence=safe_truncate(decoded[0], 250),
            weight=0,
        )
    )

    url_reports = []
    url_count = 0
    for index, value in enumerate(decoded, start=1):
        if is_http_url(value):
            url_count += 1
            report = analyze_url(value, use_intel=use_intel, online=online, intel=intel)
            url_reports.append(report.to_dict())
            if report.score > 0:
                result.add(
                    Signal(
                        id=f"qr.url_{index}",
                        title=f"QR destination #{index} has risk indicators",
                        severity=_severity_from_score(report.score),
                        category="url",
                        description="The decoded URL has its own indicators; review the URL report.",
                        evidence=safe_truncate(value, 250),
                        weight=min(60, max(10, report.score // 2)),
                    )
                )
                for signal in report.signals[:3]:
                    if signal.weight >= 20:
                        result.add(
                            Signal(
                                id=f"qr.url_{index}.{signal.id}",
                                title=f"QR destination #{index}: {signal.title}",
                                severity=signal.severity,
                                category="url",
                                description=signal.description,
                                evidence=safe_truncate(signal.evidence, 250),
                                weight=min(45, round(signal.weight * 0.55)),
                                source=signal.source,
                            )
                        )
        else:
            hits = contains_any(value, CREDENTIAL_WORDS | {"bitcoin", "btc", "upi", "wallet", "payment"})
            if hits:
                result.add(
                    Signal(
                        id=f"qr.text_{index}",
                        title="QR contains payment or credential text",
                        severity=Severity.MEDIUM,
                        category="qr",
                        description="The QR code does not contain a normal web URL but asks for sensitive information.",
                        evidence=", ".join(hits[:6]),
                        weight=20,
                    )
                )
            else:
                result.add(
                    Signal(
                        id=f"qr.text_{index}",
                        title="QR contains non-URL text",
                        severity=Severity.LOW,
                        category="qr",
                        description="The content is not a standard web link; inspect it before acting.",
                        evidence=safe_truncate(value, 250),
                        weight=5,
                    )
                )

    result.metadata["url_count"] = url_count
    result.metadata["url_reports"] = url_reports
    result.recommendations = [
        "Preview the decoded destination and confirm the exact domain before opening it.",
        "Do not scan QR codes from unexpected stickers, invoices, or messages.",
        "Never enter credentials or payment details from a QR-code landing page.",
        "If the code claims to be from an organisation, open its official app instead.",
    ]
    return finalize(result)


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
