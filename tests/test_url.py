from unittest.mock import patch
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

def test_invalid_text_port_returns_controlled_error():
    result = analyze_url("https://example.com:abc", online=False)

    assert result.error is not None
    assert "Invalid URL" in result.error
    assert result.verdict is Verdict.UNKNOWN


def test_out_of_range_port_returns_controlled_error():
    result = analyze_url("https://example.com:99999", online=False)

    assert result.error is not None
    assert "Invalid URL" in result.error
    assert result.verdict is Verdict.UNKNOWN


def test_valid_https_port_is_accepted():
    result = analyze_url("https://example.com:443", online=False)

    assert result.error is None

from unittest.mock import patch
from phishguard.utils import resolve_public_ips


def test_dns_public_ip_allowed():
    with patch("phishguard.utils.dns.resolver.Resolver") as resolver:
        resolver.return_value.resolve.side_effect = (
            lambda host, record_type:
            ["8.8.8.8"] if record_type == "A" else []
        )
        assert resolve_public_ips("test.example.com") == ["8.8.8.8"]


def test_dns_private_ip_blocked():
    with patch("phishguard.utils.dns.resolver.Resolver") as resolver:
        resolver.return_value.resolve.side_effect = (
            lambda host, record_type:
            ["192.168.1.10"] if record_type == "A" else []
        )
        assert resolve_public_ips("test.example.com") == []


def test_dns_mixed_ips_blocked():
    with patch("phishguard.utils.dns.resolver.Resolver") as resolver:
        resolver.return_value.resolve.side_effect = (
            lambda host, record_type:
            ["8.8.8.8", "127.0.0.1"] if record_type == "A" else []
        )
        assert resolve_public_ips("test.example.com") == []


def test_dns_ipv6_localhost_blocked():
    with patch("phishguard.utils.dns.resolver.Resolver") as resolver:
        resolver.return_value.resolve.side_effect = (
            lambda host, record_type:
            ["::1"] if record_type == "AAAA" else []
        )
        assert resolve_public_ips("test.example.com") == []

def test_tls_does_not_connect_when_ip_rejected():
    from phishguard.utils import tls_certificate

    with patch(
        "phishguard.utils.resolve_public_ips",
        return_value=[]
    ), patch(
        "phishguard.utils.socket.create_connection"
    ) as connection:
        result = tls_certificate("internal.example.com")

    assert result["ok"] is False
    connection.assert_not_called()


def test_tls_uses_validated_public_ip():
    from phishguard.utils import tls_certificate

    with patch(
        "phishguard.utils.resolve_public_ips",
        return_value=["8.8.8.8"]
    ), patch(
        "phishguard.utils.socket.create_connection",
        side_effect=OSError("Simulated connection failure")
    ) as connection:
        result = tls_certificate("example.com")

    connection.assert_called_once_with(
        ("8.8.8.8", 443),
        timeout=4
    )
    assert result["ok"] is False
def test_rdap_disables_automatic_redirects():
    from unittest.mock import Mock, patch
    from phishguard.utils import rdap_domain_age_days

    response = Mock()
    response.status_code = 302

    rdap_domain_age_days.cache_clear()

    with patch(
        "phishguard.utils.requests.get",
        return_value=response,
    ) as mock_get:
        result = rdap_domain_age_days("example.com")

    assert result is None
    assert mock_get.call_args.kwargs["allow_redirects"] is False

    rdap_domain_age_days.cache_clear()
def test_intel_get_disables_automatic_redirects():
    from unittest.mock import Mock, patch
    from phishguard.intel import IntelClient

    response = Mock()
    response.status_code = 302

    client = IntelClient()

    with patch(
        "phishguard.intel.requests.get",
        return_value=response,
    ) as mock_get:
        result = client._get("https://example.com/api")

    assert result is response
    assert mock_get.call_args.kwargs["allow_redirects"] is False
def test_google_safe_browsing_disables_redirects():
    from unittest.mock import Mock, patch
    from phishguard.intel import IntelClient

    client = IntelClient(safe_browsing_key="fake-test-key")

    response = Mock()
    response.status_code = 302

    with patch(
        "phishguard.intel.requests.post",
        return_value=response,
    ) as mock_post:
        result = client.google_safe_browsing(
            "https://example.com"
        )

    assert result.source == "Google Safe Browsing"
    assert result.error == "HTTP 302"
    assert mock_post.call_args.kwargs["allow_redirects"] is False
