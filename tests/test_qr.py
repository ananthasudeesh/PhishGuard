import cv2

from phishguard.analyzers.qr import analyze_qr, decode_qr
from phishguard.models import Verdict


def make_qr(value: str) -> bytes:
    encoder = cv2.QRCodeEncoder.create()
    image = encoder.encode(value)
    image = cv2.resize(image, (300, 300), interpolation=cv2.INTER_NEAREST)
    image = cv2.copyMakeBorder(image, 40, 40, 40, 40, cv2.BORDER_CONSTANT, value=255)
    ok, buffer = cv2.imencode(".png", image)
    assert ok
    return buffer.tobytes()


def test_decode_qr():
    assert decode_qr(make_qr("https://example.com")) == ["https://example.com"]


def test_qr_to_suspicious_url():
    result = analyze_qr(make_qr("http://paypa1.com/login"), "qr.png", online=False)
    assert result.metadata["decoded_values"] == ["http://paypa1.com/login"]
    assert result.verdict in {Verdict.SUSPICIOUS, Verdict.MALICIOUS}
    assert any(signal.id.startswith("qr.url_") for signal in result.signals)


def test_non_qr_image():
    result = analyze_qr(b"not an image", "bad.png", online=False)
    assert result.error
