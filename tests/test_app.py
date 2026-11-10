from pathlib import Path

from streamlit.testing.v1 import AppTest

APP = Path(__file__).resolve().parents[1] / "app.py"


def test_all_tabs_render():
    app = AppTest.from_file(str(APP), default_timeout=30)
    app.run()
    assert not app.exception
    assert [tab.label for tab in app.tabs] == [
        "🔗 URL",
        "📧 Email",
        "🔳 QR code",
        "📎 File",
        "💬 Social media",
    ]
    assert [button.label for button in app.button] == [
        "Analyze URL",
        "Analyze email",
        "Analyze QR code",
        "Analyze file",
        "Analyze message",
    ]
