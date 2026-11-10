# 🛡️ PhishGuard

**Automated, explainable phishing triage for email, links, QR codes, files, and social-media messages.**

PhishGuard is a defensive cybersecurity project that helps ordinary users, students, small businesses, and SOC analysts decide whether a suspicious message or file is safe to interact with. It combines transparent rule-based detection with optional threat-intelligence lookups and produces a downloadable report.

> **Public demo:** `https://<your-app>.streamlit.app` (replace after deployment)  
> **Documentation:** [`documentation/`](documentation/)  
> **Status:** working MVP — public-launch hardening in progress.

---

## Why PhishGuard?

Phishing is no longer only an email problem. Attacks arrive through:

- fake login links and shortened URLs,
- QR codes on posters, invoices, and restaurant tables,
- malicious attachments and macro-enabled documents,
- Instagram/WhatsApp/Telegram investment, job, and support scams.

Most free tools check only one input type. PhishGuard gives one consistent workflow: **paste/upload → explainable indicators → risk score → recommended action → downloadable report.**

It is deliberately **defensive**:

- no phishing-page creation,
- no credential collection,
- no attachment execution,
- no automatic browsing of suspicious links,
- no storage of uploaded emails or files.

---

## Features

| Input | What PhishGuard checks |
| --- | --- |
| 🔗 **URL** | lexical tricks, punycode/homographs, lookalike brands, shorteners, suspicious TLDs, raw IPs, credentials in URL, DNS, TLS certificate, domain age via RDAP, optional VirusTotal / Google Safe Browsing / urlscan.io |
| 📧 **Email (.eml)** | From/Reply-To/Return-Path mismatches, display-name spoofing, SPF/DKIM/DMARC results, DMARC policy, urgency and credential language, HTML password forms, link/text mismatches, extracted URLs, attachment metadata |
| 🔳 **QR code** | local decoding with OpenCV, decoded destination preview, URL analysis, payment/credential text detection |
| 📎 **File / attachment** | SHA-256/MD5/SHA-1, magic bytes, extension mismatch, double extensions, executables, Office macros, OOXML embedded objects, PDF JavaScript/launch actions, archive bombs, path traversal, encrypted archives, script patterns, optional VirusTotal hash lookup |
| 💬 **Social media** | crypto/investment scams, prize and giveaway language, urgency, credential requests, support impersonation, off-platform pressure, job scams, shared-link analysis |

Every result includes:

- **risk score** from 0–100,
- **verdict** (`malicious`, `suspicious`, `likely safe`, `unknown`),
- **confidence** estimate,
- **individual signals** with severity, evidence, weight, and source,
- **recommended actions**,
- **JSON and Markdown reports**.

---

## Quick start (local)

### 1. Clone and enter the repository

```bash
git clone https://github.com/ananthasudeesh/PhishGuard.git
cd PhishGuard
```

### 2. Create a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 3. Optional: configure threat intelligence

```bash
cp .env.example .env
# edit .env and add your keys
```

Keys are optional. Without them, PhishGuard still performs local analysis plus public urlscan.io/RDAP checks.

### 4. Run the app

```bash
streamlit run app.py
```

Open `http://localhost:8501`.

### 5. Run the tests

```bash
PYTHONPATH=src pytest -q
```

---

## Deploy publicly (Streamlit Community Cloud)

1. Push the repository to GitHub.
2. Go to [share.streamlit.io](https://share.streamlit.io) and connect GitHub.
3. Select the repository, branch `main`, and entrypoint `app.py`.
4. In **Advanced settings → Secrets**, add:

```toml
VIRUSTOTAL_API_KEY = "your-key"
GOOGLE_SAFE_BROWSING_API_KEY = "your-key"
URLSCAN_API_KEY = "your-key"
```

5. Deploy and replace the demo link at the top of this README.

See [`documentation/04-DEPLOYMENT.md`](documentation/04-DEPLOYMENT.md) for the full checklist, custom domain, CI, and rollback.

---

## Architecture

```text
Streamlit UI (app.py)
        │
        ├── URL analyzer ──────► DNS / TLS / RDAP / optional intel
        ├── Email analyzer ────► headers / auth / body / links / attachments
        ├── QR analyzer ───────► OpenCV decode ──► URL analyzer
        ├── File analyzer ─────► magic / archives / macros / PDF / scripts
        └── Social analyzer ───► language patterns ──► URL analyzer
                                      │
                                      ▼
                         transparent scoring engine
                                      │
                                      ▼
                    verdict + evidence + recommendations
```

The MVP is a modular monolith: one Streamlit process, isolated analyzer modules, no database. This is intentional for a public, privacy-first launch. A FastAPI backend can be added later without rewriting the analyzers.

More: [`documentation/02-ARCHITECTURE.md`](documentation/02-ARCHITECTURE.md).

---

## How the score works

Each indicator has a weight from 0–100 and a confidence value. The score is:

```text
score = min(100, Σ(weight × confidence))
```

Duplicate indicator IDs keep only the strongest instance. Verdict thresholds:

| Score | Verdict |
| --- | --- |
| 70–100 | **Malicious** |
| 35–69 | **Suspicious** |
| 0–34 with indicators | **Likely safe** |
| no data | **Unknown** |

The score is **triage**, not proof. A clean result does not guarantee safety, and a high score still deserves human review.

---

## Privacy and security

- Uploaded emails, QR images, and files are processed **in memory** for the request.
- PhishGuard does **not** save uploads or generated reports on the server.
- Attachments are **never executed**.
- Suspicious pages are **never opened** in a browser.
- Threat intelligence is **opt-in**; only URLs/domains and SHA-256 hashes are sent.
- API keys live in Streamlit secrets or environment variables, never in the repository.
- DNS/TLS checks resolve a host and reject private, loopback, link-local, and reserved addresses before connecting (SSRF guard).
- Upload size and per-session rate limits reduce abuse.

See [`documentation/03-SECURITY-PRIVACY.md`](documentation/03-SECURITY-PRIVACY.md) for the threat model and the privacy-policy template.

---

## Limitations

- No sandbox detonation; file analysis is static.
- No platform APIs; social-media analysis uses pasted text and links.
- Email authentication results are parsed from headers and DNS, not a full independent SPF/DKIM verification of the raw message.
- Threat-intelligence free tiers have quotas and may rate-limit the public app.
- New phishing domains and zero-day files can look clean.
- The tool does not replace an email gateway, EDR, or a trained analyst.

---

## Project structure

```text
PhishGuard/
├── app.py                      # Streamlit entrypoint
├── src/phishguard/
│   ├── models.py               # Signal, AnalysisResult, Verdict
│   ├── scoring.py              # transparent scoring
│   ├── utils.py                # URL/DNS/TLS/file helpers + SSRF guard
│   ├── intel.py                # optional VirusTotal / GSB / urlscan
│   └── analyzers/
│       ├── url.py
│       ├── email.py
│       ├── qr.py
│       ├── file.py
│       └── social.py
├── tests/
├── documentation/
├── samples/
├── .streamlit/config.toml
├── .env.example
├── requirements.txt
└── README.md
```

---

## 30-day build plan

The complete day-by-day roadmap is in [`documentation/01-30-DAY-ROADMAP.md`](documentation/01-30-DAY-ROADMAP.md). It covers:

- Week 1: foundation, scoring engine, URL analysis, threat intelligence, deployment.
- Week 2: email parsing, authentication, attachments, email UI.
- Week 3: QR, social media, file hardening, reports, UX.
- Week 4: abuse controls, security review, privacy/legal, testing, beta, launch.

---

## Contributing

1. Fork the repository.
2. Create a branch: `git checkout -b feature/my-change`.
3. Add tests for new indicators.
4. Run `PYTHONPATH=src pytest -q`.
5. Open a pull request with a clear description and sample output.

Please do not submit real victim data, live malware, or API keys.

---

## License

MIT License. See [`LICENSE`](LICENSE).

---

## Disclaimer

PhishGuard is intended for **educational and authorised defensive cybersecurity analysis**. Findings are automated indicators for human review, not definitive proof of malicious activity. Do not use this project to create, host, or distribute phishing content. Always follow applicable privacy, computer-misuse, and data-protection laws.

---

**Developer:** Anantha Sudeesh SD  
**Repository:** https://github.com/ananthasudeesh/PhishGuard
