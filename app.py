"""PhishGuard Streamlit application.

Run locally:
    streamlit run app.py

Deploy on Streamlit Community Cloud with ``app.py`` as the entrypoint.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import streamlit as st

# Allow ``streamlit run app.py`` from the repository root.
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from phishguard.analyzers import (
    analyze_eml,
    analyze_file_bytes,
    analyze_qr,
    analyze_social,
    analyze_url,
)
from phishguard.intel import IntelClient
from phishguard.models import VERDICT_LABELS, AnalysisResult, Verdict

MAX_UPLOAD_MB = int(os.getenv("PHISHGUARD_MAX_UPLOAD_MB", "10"))
MAX_ANALYSES_PER_HOUR = int(os.getenv("PHISHGUARD_RATE_LIMIT", "20"))
REPO_URL = os.getenv("PHISHGUARD_REPO_URL", "https://github.com/ananthasudeesh/PhishGuard")

st.set_page_config(
    page_title="PhishGuard — Phishing Triage",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items={
        "Get help": REPO_URL,
        "Report a bug": f"{REPO_URL}/issues",
        "About": "PhishGuard is a defensive phishing-triage tool. Findings are indicators, not proof.",
    },
)

st.markdown(
    """
    <style>
      .block-container { padding-top: 1.2rem; }
      .pg-hero {
        padding: 1.2rem 1.4rem;
        border: 1px solid rgba(148, 163, 184, .25);
        border-radius: 16px;
        background: linear-gradient(135deg, rgba(14, 165, 233, .12), rgba(15, 23, 42, .2));
        margin-bottom: 1rem;
      }
      .pg-hero h1 { margin: 0; font-size: 2rem; }
      .pg-hero p { margin: .35rem 0 0; color: #94a3b8; }
      .pg-badge {
        display: inline-block; padding: .35rem .8rem; border-radius: 999px;
        font-weight: 700; letter-spacing: .02em; margin-bottom: .5rem;
      }
      .pg-malicious { background: #7f1d1d; color: #fecaca; }
      .pg-suspicious { background: #78350f; color: #fde68a; }
      .pg-likely-safe { background: #14532d; color: #bbf7d0; }
      .pg-unknown { background: #334155; color: #e2e8f0; }
      .pg-small { color: #94a3b8; font-size: .85rem; }
    </style>
    """,
    unsafe_allow_html=True,
)


def _secret(name: str) -> str:
    """Read a Streamlit secret, falling back to an environment variable."""
    try:
        value = st.secrets.get(name, "")
    except Exception:
        value = ""
    return str(value or os.getenv(name, "")).strip()


@st.cache_resource(show_spinner=False)
def get_intel() -> IntelClient:
    return IntelClient(
        virustotal_key=_secret("VIRUSTOTAL_API_KEY"),
        safe_browsing_key=_secret("GOOGLE_SAFE_BROWSING_API_KEY"),
        urlscan_key=_secret("URLSCAN_API_KEY"),
    )


def _rate_limit_state() -> tuple[int, int]:
    now = time.time()
    history = st.session_state.setdefault("analysis_times", [])
    history[:] = [stamp for stamp in history if now - stamp < 3600]
    return len(history), MAX_ANALYSES_PER_HOUR


def _rate_limit_ok() -> bool:
    used, limit = _rate_limit_state()
    return used < limit


def _record_analysis() -> None:
    st.session_state.setdefault("analysis_times", []).append(time.time())


def _run(label: str, fn, *args, **kwargs) -> None:
    if not _rate_limit_ok():
        st.error("Hourly analysis limit reached. Please try again later.")
        return
    with st.spinner(f"Analyzing {label}…"):
        try:
            result = fn(*args, **kwargs)
        except Exception as exc:  # keep the public app from exposing a traceback
            result = AnalysisResult(
                analyzer=label.title(),
                target="analysis",
                error=f"Unexpected analysis error: {type(exc).__name__}",
            )
    _record_analysis()
    st.session_state["last_result"] = result


def _verdict_class(verdict: Verdict) -> str:
    return {
        Verdict.MALICIOUS: "pg-malicious",
        Verdict.SUSPICIOUS: "pg-suspicious",
        Verdict.LIKELY_SAFE: "pg-likely-safe",
        Verdict.UNKNOWN: "pg-unknown",
    }[verdict]


def render_result(result: AnalysisResult, key: str) -> None:
    st.divider()
    st.subheader("Analysis result")
    if result.error:
        st.error(result.error)
        if not result.signals:
            return

    label = VERDICT_LABELS[result.verdict]
    st.markdown(
        f'<span class="pg-badge {_verdict_class(result.verdict)}">{label}</span>',
        unsafe_allow_html=True,
    )
    left, middle, right = st.columns([1, 1, 2])
    left.metric("Risk score", f"{result.score}/100")
    middle.metric("Confidence", f"{round(result.confidence * 100)}%")
    right.metric("Indicators", len(result.signals))
    st.progress(result.score / 100)
    st.write(result.summary)
    st.caption(
        "Automated indicators are for human review. A low score does not guarantee safety."
    )

    if result.signals:
        rows = [
            {
                "Severity": signal.severity.value.upper(),
                "Indicator": signal.title,
                "Evidence": signal.evidence,
                "Weight": signal.weight,
                "Source": signal.source,
            }
            for signal in result.signals
        ]
        st.dataframe(rows, width="stretch", hide_index=True)

    if result.recommendations:
        st.markdown("**Recommended actions**")
        for item in result.recommendations:
            st.markdown(f"- {item}")

    with st.expander("Technical details"):
        st.json(result.metadata)

    report_json = json.dumps(result.to_dict(), indent=2, ensure_ascii=False)
    report_md = result.to_markdown()
    download_left, download_right = st.columns(2)
    with download_left:
        st.download_button(
            "Download JSON report",
            data=report_json,
            file_name=f"phishguard-{result.analyzer.lower().replace(' ', '-')}.json",
            mime="application/json",
            key=f"json-{key}",
        )
    with download_right:
        st.download_button(
            "Download Markdown report",
            data=report_md,
            file_name=f"phishguard-{result.analyzer.lower().replace(' ', '-')}.md",
            mime="text/markdown",
            key=f"md-{key}",
        )


def _intel_control(key: str) -> bool:
    intel = get_intel()
    configured = bool(intel.virustotal_key or intel.safe_browsing_key or intel.urlscan_key)
    help_text = (
        "Sends only the URL/domain or SHA-256 hash to the selected services. "
        "Raw email bodies and files never leave this app."
    )
    if not configured:
        help_text += " No API keys are configured, so only public urlscan.io and RDAP are used."
    return st.checkbox(
        "Use opt-in threat intelligence (URLs and hashes only)",
        value=False,
        help=help_text,
        key=key,
    )


def url_tab() -> None:
    st.markdown("#### Check a link before you click it")
    st.caption(
        "PhishGuard inspects the URL structure, DNS, TLS certificate, domain age, and optional reputation data. "
        "It never opens the page in a browser."
    )
    with st.form("url-form"):
        url = st.text_input("URL", placeholder="https://example.com/login")
        use_intel = _intel_control("url-intel")
        submitted = st.form_submit_button("Analyze URL", type="primary", use_container_width=True)
    if submitted:
        if not url.strip():
            st.warning("Enter a URL first.")
        else:
            _run("URL", analyze_url, url, use_intel=use_intel, online=True, intel=get_intel())
    result = st.session_state.get("last_result")
    if result and result.analyzer == "URL":
        render_result(result, "url")


def email_tab() -> None:
    st.markdown("#### Investigate a suspicious email")
    st.caption(
        "Upload an exported .eml file. PhishGuard reads headers, authentication results, links, HTML forms, "
        "and attachment metadata. It does not open attachments or load remote images."
    )
    with st.form("email-form"):
        upload = st.file_uploader("Email file (.eml)", type=["eml", "txt"], accept_multiple_files=False)
        use_intel = _intel_control("email-intel")
        submitted = st.form_submit_button("Analyze email", type="primary", use_container_width=True)
    if submitted:
        if upload is None:
            st.warning("Upload an .eml file first.")
        else:
            data = upload.getvalue()
            if len(data) > MAX_UPLOAD_MB * 1024 * 1024:
                st.error(f"File is larger than the {MAX_UPLOAD_MB} MB limit.")
            else:
                _run(
                    "Email",
                    analyze_eml,
                    data,
                    upload.name,
                    use_intel=use_intel,
                    online=True,
                    intel=get_intel(),
                )
    result = st.session_state.get("last_result")
    if result and result.analyzer == "Email":
        render_result(result, "email")


def qr_tab() -> None:
    st.markdown("#### Decode a QR code safely")
    st.caption(
        "The QR image is decoded in memory. The destination is then checked with the URL analyzer before you open it."
    )
    with st.form("qr-form"):
        upload = st.file_uploader("QR image", type=["png", "jpg", "jpeg", "webp"], accept_multiple_files=False)
        use_intel = _intel_control("qr-intel")
        submitted = st.form_submit_button("Analyze QR code", type="primary", use_container_width=True)
    if submitted:
        if upload is None:
            st.warning("Upload a QR image first.")
        else:
            data = upload.getvalue()
            if len(data) > MAX_UPLOAD_MB * 1024 * 1024:
                st.error(f"Image is larger than the {MAX_UPLOAD_MB} MB limit.")
            else:
                _run(
                    "QR Code",
                    analyze_qr,
                    data,
                    upload.name,
                    use_intel=use_intel,
                    online=True,
                    intel=get_intel(),
                )
    result = st.session_state.get("last_result")
    if result and result.analyzer == "QR Code":
        render_result(result, "qr")


def file_tab() -> None:
    st.markdown("#### Inspect an attachment")
    st.caption(
        "Static analysis only: magic bytes, extension mismatch, macros, PDF actions, archive contents, scripts, "
        "and an optional SHA-256 reputation lookup. Files are never executed or uploaded."
    )
    with st.form("file-form"):
        upload = st.file_uploader("Attachment", accept_multiple_files=False)
        use_intel = _intel_control("file-intel")
        submitted = st.form_submit_button("Analyze file", type="primary", use_container_width=True)
    if submitted:
        if upload is None:
            st.warning("Upload a file first.")
        else:
            data = upload.getvalue()
            if len(data) > MAX_UPLOAD_MB * 1024 * 1024:
                st.error(f"File is larger than the {MAX_UPLOAD_MB} MB limit.")
            else:
                _run(
                    "File",
                    analyze_file_bytes,
                    data,
                    upload.name,
                    use_intel=use_intel,
                    online=True,
                    intel=get_intel(),
                )
    result = st.session_state.get("last_result")
    if result and result.analyzer == "File":
        render_result(result, "file")


def social_tab() -> None:
    st.markdown("#### Triage a social-media message or profile text")
    st.caption(
        "Paste the message text. PhishGuard looks for scam language and checks any shared links. "
        "It does not scrape private accounts or bypass platform login walls."
    )
    with st.form("social-form"):
        platform = st.selectbox(
            "Platform",
            ["Unspecified", "WhatsApp", "Telegram", "Instagram", "Facebook", "X / Twitter", "LinkedIn", "Other"],
        )
        text = st.text_area(
            "Message text",
            height=180,
            placeholder="Paste the suspicious message, job offer, investment pitch, or profile bio…",
        )
        use_intel = _intel_control("social-intel")
        submitted = st.form_submit_button("Analyze message", type="primary", use_container_width=True)
    if submitted:
        if not text.strip():
            st.warning("Paste some message text first.")
        else:
            _run(
                "Social Media",
                analyze_social,
                text,
                "" if platform == "Unspecified" else platform,
                use_intel=use_intel,
                online=True,
                intel=get_intel(),
            )
    result = st.session_state.get("last_result")
    if result and result.analyzer == "Social Media":
        render_result(result, "social")


def sidebar() -> None:
    intel = get_intel()
    st.sidebar.title("🛡️ PhishGuard")
    st.sidebar.caption("Defensive phishing triage for everyone")
    st.sidebar.markdown(
        "Analyze **links, emails, QR codes, attachments, and social messages** in one place."
    )

    used, limit = _rate_limit_state()
    st.sidebar.markdown("#### Session usage")
    st.sidebar.progress(min(1.0, used / limit) if limit else 0.0)
    st.sidebar.caption(f"{used} of {limit} analyses used this hour")

    st.sidebar.markdown("#### Threat intelligence")
    st.sidebar.write("VirusTotal: " + ("✅ configured" if intel.virustotal_key else "— not configured"))
    st.sidebar.write("Safe Browsing: " + ("✅ configured" if intel.safe_browsing_key else "— not configured"))
    st.sidebar.write("urlscan.io: " + ("✅ key configured" if intel.urlscan_key else "public mode"))
    st.sidebar.caption("Intel is opt-in per analysis. Only URLs/domains and SHA-256 hashes are sent.")

    with st.sidebar.expander("Privacy and limits"):
        st.write(
            "- Uploaded data is processed in memory for this request.\n"
            "- PhishGuard does not save emails, files, or QR images.\n"
            "- No attachment is executed and no page is opened.\n"
            "- Do not upload data you are not authorised to analyse.\n"
            f"- Maximum upload: {MAX_UPLOAD_MB} MB.\n"
            f"- Rate limit: {MAX_ANALYSES_PER_HOUR} analyses per session per hour."
        )
    with st.sidebar.expander("How the score works"):
        st.write(
            "Each indicator has a transparent weight. The score is the capped sum of "
            "weight × confidence. **70+** is treated as malicious, **35–69** as suspicious, "
            "and below 35 as likely safe. It is triage, not a verdict."
        )
    st.sidebar.markdown(f"[Source code]({REPO_URL}) · [Report an issue]({REPO_URL}/issues)")
    st.sidebar.caption("Educational and defensive use only. Findings are indicators, not proof.")


def main() -> None:
    st.markdown(
        """
        <div class="pg-hero">
          <h1>🛡️ PhishGuard</h1>
          <p>Automated phishing triage for email, links, QR codes, files, and social messages.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.info(
        "PhishGuard is a defensive triage tool. It does not guarantee that a message is safe. "
        "When in doubt, verify through an official channel.",
        icon="ℹ️",
    )
    sidebar()

    tabs = st.tabs(["🔗 URL", "📧 Email", "🔳 QR code", "📎 File", "💬 Social media"])
    with tabs[0]:
        url_tab()
    with tabs[1]:
        email_tab()
    with tabs[2]:
        qr_tab()
    with tabs[3]:
        file_tab()
    with tabs[4]:
        social_tab()

    st.divider()
    st.caption(
        "PhishGuard · Defensive analysis only · No email or file storage · "
        "Findings are indicators for human review, not definitive proof."
    )


if __name__ == "__main__":
    main()
