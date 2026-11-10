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
