from phishguard.analyzers.url import analyze_url
from phishguard.models import Verdict
from phishguard.utils import extract_urls, registered_domain


def test_lookalike_domain_is_suspicious_without_network():
    result = analyze_url("http://paypa1.com/verify-account/login", online=False)
    assert result.verdict is Verdict.SUSPICIOUS
    assert any(signal.id == "url.brand_lookalike" for signal in result.signals)
    assert any(signal.id == "url.credential_keywords" for signal in result.signals)


def test_private_ip_is_critical():
    result = analyze_url("http://192.168.1.10/login", online=False)
    assert any(signal.id == "url.private_ip" for signal in result.signals)
    assert result.score >= 70


def test_shortener_and_http_are_flagged():
    result = analyze_url("http://bit.ly/abc123", online=False)
    assert any(signal.id == "url.shortener" for signal in result.signals)
    assert any(signal.id == "url.no_https" for signal in result.signals)


def test_clean_url_has_no_high_severity_signal():
    result = analyze_url("https://www.google.com/search?q=phishing", online=False)
    assert result.verdict is Verdict.LIKELY_SAFE
    assert not any(signal.severity.value in {"high", "critical"} for signal in result.signals)


def test_extract_urls_deduplicates_scheme_variants():
    urls = extract_urls("See http://bit.ly/abc and bit.ly/abc, then https://example.com")
    assert urls == ["http://bit.ly/abc", "https://example.com"]


def test_registered_domain():
    assert registered_domain("https://login.paypal.com.evil.com/path") == "evil.com"
    assert registered_domain("https://www.google.co.in") == "google.co.in"
