# PhishGuard — Testing Guide

> **Principle:** every detection rule gets a test with a malicious and a benign example. A rule without a test is a guess.

---

## 1. Test layers

| Layer | What | Speed | Examples |
| --- | --- | --- | --- |
| Unit | Pure functions, one signal | ms | lookalike domain, score cap, file magic |
| Analyzer | One input → one result | ms | `.eml` → email result, QR → URL result |
| Integration | Multiple modules | 100 ms | email links → URL analyzer → score |
| UI smoke | Streamlit renders | seconds | all tabs, buttons, no exception |
| Security | Hostile input | ms | private IP, zip bomb, traversal, oversized |
| Manual | Real sanitized samples | minutes | mobile, slow network, API failure |

---

## 2. Run the suite

```bash
cd ~/PhishGuard
source .venv/bin/activate
PYTHONPATH=src pytest -q
```

Expected current result:

```text
22 passed
```

Verbose:

```bash
PYTHONPATH=src pytest -v
```

One file:

```bash
PYTHONPATH=src pytest tests/test_url.py -q
```

One test:

```bash
PYTHONPATH=src pytest tests/test_url.py::test_private_ip_is_critical -q
```

---

## 3. What to test per analyzer

### Scoring

- Empty signals → unknown.
- Info-only signals → likely safe.
- 35 → suspicious.
- 70 → malicious.
- Duplicate IDs keep the strongest.
- Score is capped at 100.
- Recommendations are generated.

### URL

- Lookalike domain (`paypa1.com`).
- Leet-speak (`paypa1`, `micros0ft`).
- Punycode (`xn--...`).
- Raw IP.
- Private IP (critical).
- Shortener.
- Suspicious TLD.
- `@` credentials.
- Unusual port.
- No HTTPS.
- Long URL.
- Credential path keywords.
- Executable download.
- Clean URL (no high/critical).
- URL extraction/dedup.

### Email

- From/Reply-To mismatch.
- Return-Path mismatch.
- Display-name brand spoof.
- Lookalike sender domain.
- SPF/DKIM/DMARC fail.
- Missing DMARC.
- Password form.
- Link text vs href mismatch.
- URL extraction.
- Attachment signals.
- Benign newsletter.
- Malformed message.
- Oversized message.

### QR

- Generated QR decodes.
- URL QR → URL result.
- Non-URL QR → text signal.
- No QR → error result.
- Invalid image → error result.
- Multiple QR codes (if supported).

### File

- `MZ` executable.
- `invoice.pdf.exe`.
- PDF `/JavaScript`.
- OOXML `vbaProject.bin`.
- ZIP with `../payload.exe`.
- ZIP bomb metadata.
- Encrypted ZIP.
- LNK/ISO/OneNote signatures.
- Plain text (benign).
- Random bytes (no crash).

### Social

- Crypto/investment pitch.
- Prize/giveaway.
- Credential request.
- Brand support impersonation.
- Off-platform pressure.
- Job scam.
- Shared malicious link.
- Benign message.

---

## 4. Test fixtures

Put synthetic samples in `samples/`:

```text
samples/
├── benign/
│   ├── newsletter.eml
│   ├── notes.txt
│   └── normal-qr.png
└── phishing/
    ├── reply-to-spoof.eml
    ├── spf-fail.eml
    ├── invoice.pdf.exe
    ├── macro.docx
    └── suspicious-qr.png
```

Rules:

- Never commit real victim emails, personal data, or live malware.
- Use fake domains like `example.com`, `paypa1.com`, `evil.test`.
- For malware-like samples, use inert bytes (`MZ` + zeros), not working payloads.
- Document what each sample is for.

---

## 5. Mocking network calls

Unit tests should not depend on the internet. Use the `online=False` flag where available:

```python
result = analyze_url("http://paypa1.com/login", online=False)
```

For code paths that need DNS/TLS, monkeypatch:

```python
def test_private_ip(monkeypatch):
    monkeypatch.setattr("phishguard.utils.resolve_public_ips", lambda host: [])
    ...
```

For intel, inject a fake client:

```python
class FakeIntel:
    virustotal_key = ""
    safe_browsing_key = ""
    urlscan_key = ""
    def virustotal_url(self, url):
        ...
```

Keep a small number of opt-in integration tests that hit real services, and never run them in CI by default.

---

## 6. Streamlit UI smoke test

```python
from streamlit.testing.v1 import AppTest

def test_app_renders():
    at = AppTest.from_file("app.py", default_timeout=30)
    at.run()
    assert not at.exception
    assert [tab.label for tab in at.tabs] == [
        "🔗 URL", "📧 Email", "🔳 QR code", "📎 File", "💬 Social media"
    ]
```

Add this to `tests/test_app.py`.

---

## 7. Security tests

### SSRF

```python
def test_private_ip_is_critical():
    result = analyze_url("http://192.168.1.10/login", online=False)
    assert any(s.id == "url.private_ip" for s in result.signals)
```

Also test:

- `http://127.0.0.1/`
- `http://[::1]/`
- `http://169.254.169.254/latest/meta-data/`
- `http://10.0.0.1/`
- a hostname resolving to a private IP (mock).

### Zip bomb / traversal

- Build a ZIP with `../../payload.exe`.
- Build a ZIP with many entries.
- Build a ZIP with a high compression ratio.
- Assert signals and no extraction.

### Oversized input

- A 30 MB file returns an error result.
- The app rejects a 20 MB upload before parsing.

### XSS

- A filename like `<img src=x onerror=alert(1)>.pdf` is rendered as text/data, not HTML.
- A URL with `<script>` is not rendered as HTML.

### Secrets

- `git grep` for keys.
- `pip-audit` for dependency issues.

---

## 8. Coverage

```bash
pip install pytest-cov
PYTHONPATH=src pytest --cov=src/phishguard --cov-report=term-missing
```

Target:

- 80%+ on `scoring.py`, `utils.py`, and core analyzer branches.
- 100% on the verdict thresholds.
- Do not chase 100% coverage on defensive `except` branches.

---

## 9. CI

`.github/workflows/tests.yml`:

```yaml
name: tests

on:
  push:
    branches: [main]
  pull_request:

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
          cache: pip
      - run: |
          python -m pip install --upgrade pip
          pip install -r requirements.txt
      - env:
          PYTHONPATH: src
        run: pytest -q
```

Add `ruff` and `mypy` when the core modules are stable.

---

## 10. Manual test script (5 minutes)

1. Open the public app on a phone.
2. URL: `https://www.google.com` → likely safe.
3. URL: `http://paypa1.com/verify-account/login` → suspicious.
4. Email: upload `samples/phishing/reply-to-spoof.eml` → suspicious/malicious.
5. QR: upload `samples/phishing/suspicious-qr.png` → decoded + suspicious.
6. File: upload `samples/phishing/invoice.pdf.exe` → malicious.
7. Social: paste a crypto/Telegram pitch → suspicious.
8. Download JSON and Markdown.
9. Confirm no error traceback.
10. Confirm the privacy note is visible.

---

## 11. Definition of done

- [ ] New rule has a malicious test.
- [ ] New rule has a benign test.
- [ ] `PYTHONPATH=src pytest -q` passes.
- [ ] No network dependency in unit tests.
- [ ] No real victim data or live malware in fixtures.
- [ ] CI is green.
- [ ] Manual smoke test passes.
- [ ] README/docs updated.
