from phishguard.analyzers.social import analyze_social
from phishguard.models import Verdict


def test_investment_scam_language():
    result = analyze_social(
        "Guaranteed crypto profit! Send USDT to this wallet and double your money. DM me on Telegram.",
        platform="Instagram",
        online=False,
    )
    ids = {signal.id for signal in result.signals}
    assert "social.crypto" in ids
    assert "social.offplatform" in ids
    assert result.verdict is Verdict.SUSPICIOUS


def test_credential_phishing_language():
    result = analyze_social(
        "Official support team: your account is suspended. Verify your account and send the OTP now.",
        platform="WhatsApp",
        online=False,
    )
    ids = {signal.id for signal in result.signals}
    assert "social.credentials" in ids
    assert "social.impersonation" in ids


def test_benign_message():
    result = analyze_social("Hey, are we still meeting for coffee at 5?", online=False)
    assert result.verdict is Verdict.LIKELY_SAFE
    assert result.score < 35
