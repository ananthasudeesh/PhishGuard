from phishguard.analyzers.email import analyze_eml
from phishguard.models import Verdict

PHISHING_EML = b"""From: "PayPal Support" <support@paypa1.com>
Reply-To: recovery@evil.example
Return-Path: <bounce@evil.example>
To: victim@example.com
Subject: Urgent: verify your account now
Date: Tue, 10 Nov 2026 10:00:00 +0000
Message-ID: <abc123@evil.example>
Authentication-Results: mx.example; spf=fail; dkim=none; dmarc=fail
MIME-Version: 1.0
Content-Type: text/html; charset=utf-8

<html><body>
<p>Your account is suspended. Verify immediately.</p>
<form action="http://paypa1.com/login"><input type="password" name="password"></form>
<a href="http://paypa1.com/login">https://www.paypal.com/login</a>
</body></html>
"""

BENIGN_EML = b"""From: Friend <friend@example.com>
To: me@example.com
Subject: Lunch tomorrow?
Date: Tue, 10 Nov 2026 10:00:00 +0000
Message-ID: <hello@example.com>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8

See you at noon.
"""


def test_phishing_email_signals():
    result = analyze_eml(PHISHING_EML, "phish.eml", online=False)
    ids = {signal.id for signal in result.signals}
    assert "email.reply_to_mismatch" in ids
    assert "email.display_name_spoof" in ids
    assert "email.auth_spf_fail" in ids
    assert "email.auth_dmarc_fail" in ids
    assert "email.password_form" in ids
    assert result.verdict in {Verdict.SUSPICIOUS, Verdict.MALICIOUS}
    assert result.score >= 35


def test_benign_email_is_not_malicious():
    result = analyze_eml(BENIGN_EML, "benign.eml", online=False)
    assert result.verdict is Verdict.LIKELY_SAFE
    assert result.score < 35
def test_empty_email_returns_error():
    result = analyze_eml(
        b"",
        "empty.eml",
        online=False,
    )

    assert result.error == "Empty email file"
def test_oversized_email_returns_error():
    oversized_data = b"A" * (25 * 1024 * 1024 + 1)

    result = analyze_eml(
        oversized_data,
        "large.eml",
        online=False,
    )

    assert result.error == (
        "Email is larger than the 25 MB analysis limit"
    )
def test_email_without_headers_is_flagged():
    invalid_data = b"This is not a properly formatted email."

    result = analyze_eml(
        invalid_data,
        "invalid.eml",
        online=False,
    )

    signal_ids = {signal.id for signal in result.signals}

    assert "email.no_headers" in signal_ids
def test_email_url_analysis_limit():
    urls = "\n".join(
        f"https://example{i}.com"
        for i in range(10)
    )

    email_data = (
        "From: sender@example.com\n"
        "To: recipient@example.com\n"
        "Subject: URL limit test\n"
        "Content-Type: text/plain; charset=utf-8\n"
        "\n"
        f"{urls}\n"
    ).encode("utf-8")

    result = analyze_eml(
        email_data,
        "many-links.eml",
        online=False,
        max_urls=5,
    )

    assert result.metadata["url_count"] == 10
    assert len(result.metadata["url_reports"]) == 5
def test_email_attachment_analysis_limit():
    from email.message import EmailMessage

    message = EmailMessage()
    message["From"] = "sender@example.com"
    message["To"] = "recipient@example.com"
    message["Subject"] = "Attachment limit test"
    message.set_content("Testing attachment limits.")

    for i in range(7):
        message.add_attachment(
            f"Harmless test file {i}".encode(),
            maintype="application",
            subtype="octet-stream",
            filename=f"test{i}.txt",
        )

    result = analyze_eml(
        message.as_bytes(),
        "attachments.eml",
        online=False,
        max_attachments=5,
    )

    assert result.metadata["attachment_count"] == 5
    assert len(result.metadata["attachment_reports"]) == 5
