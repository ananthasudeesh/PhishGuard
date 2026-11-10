# PhishGuard — Launch Templates

> These are starting points, not legal advice. Replace every `<...>` placeholder and have the final text reviewed for your jurisdiction.

---

## 1. Short project description

**One line**

> PhishGuard is a free, explainable phishing-triage app for suspicious links, emails, QR codes, attachments, and social-media messages.

**Short paragraph**

> PhishGuard helps people check a suspicious message before they click, open, or pay. Paste a URL, upload an `.eml` or attachment, scan a QR image, or paste a social-media message. PhishGuard explains the risk signals, gives a 0–100 score, and recommends a safe next step. It is defensive-only: no attachment execution, no page browsing, and no storage of your uploads.

**Portfolio bullet**

> Built and deployed a public phishing-triage web app with five analyzers, transparent rule-based scoring, DNS/TLS/RDAP enrichment, opt-in threat intelligence, SSRF-safe URL handling, in-memory file analysis, rate limits, and a pytest/CI pipeline.

---

## 2. Privacy policy template

```markdown
# PhishGuard Privacy Policy

**Last updated:** <date>

PhishGuard ("we", "us") is a free defensive phishing-analysis tool available at <URL>.

## What we process

When you use PhishGuard, you may submit:
- a URL,
- an email file (.eml),
- a QR-code image,
- a file or attachment,
- social-media message text.

We also receive standard technical information from our hosting provider, such as
IP address, browser type, and request time, to operate and secure the service.

We do not require an account and do not ask for your name, email address, or phone number.

## How we use it

We use your input only to:
- perform the analysis you requested,
- display the result and generate a report,
- protect the service from abuse and attacks,
- diagnose errors and improve reliability.

We do not use your uploads for advertising, profiling, or training machine-learning models.

## Retention

Uploaded emails, files, QR images, and message text are processed in memory for the
request and are not stored by PhishGuard.

<If your host keeps access logs, describe the retention period here.>

Generated reports are downloaded by you; we do not keep a copy.

## Third parties

Threat-intelligence lookups are optional and off by default. If you enable them:
- VirusTotal may receive a URL or SHA-256 hash.
- Google Safe Browsing may receive a URL.
- urlscan.io may receive a domain.
- RDAP/DNS providers receive the domain/hostname for registration and DNS checks.

We do not send raw email bodies, attachment bytes, or filenames to these services.
See their privacy policies for their retention practices.

## Your rights

Depending on your jurisdiction, you may have rights to access, correct, delete, or
object to the processing of your personal data. Contact us at <privacy@example.com>.

## Children

PhishGuard is not directed at children under <16/18> and we do not knowingly collect
their personal data.

## Security

We use HTTPS, in-memory processing, upload limits, rate limits, and server-side secrets.
No method of transmission or storage is completely secure.

## Changes

We may update this policy. The "Last updated" date will change.

## Contact

<name / organisation>  
<email>  
<address, if required>
```

---

## 3. Terms of use template

```markdown
# PhishGuard Terms of Use

**Last updated:** <date>

By using PhishGuard, you agree to these terms.

## Acceptable use

PhishGuard is for defensive, educational, and authorised security analysis.
You may use it to inspect messages, links, files, and QR codes that you have the
right to examine.

## Prohibited use

You must not use PhishGuard to:
- create, host, or distribute phishing content,
- collect credentials or personal data from others,
- scan systems without authorisation,
- distribute malware,
- harass, threaten, or deceive others,
- violate any applicable law.

## No warranty

PhishGuard is provided "as is" without warranties of any kind. Results are automated
indicators, not proof that a message, link, or file is safe or malicious.

## Limitation of liability

To the maximum extent permitted by law, we are not liable for any damages arising
from your use of PhishGuard or reliance on its results.

## Intellectual property

The source code is licensed under <MIT License>. The PhishGuard name and branding
remain the property of <owner>.

## Termination

We may limit or suspend access to protect the service or comply with the law.

## Governing law

These terms are governed by the laws of <jurisdiction>.

## Contact

<email>
```

---

## 4. Disclaimer (in-app and README)

```markdown
## Disclaimer

PhishGuard is a defensive triage tool. Its findings are automated indicators for
human review, not definitive proof that a message, link, file, or account is safe
or malicious.

- A low score does not guarantee safety.
- A high score does not prove malicious intent.
- New phishing domains and zero-day files may look clean.
- PhishGuard does not execute attachments or browse suspicious pages.

When in doubt, verify through an official channel you found independently.
```

---

## 5. Security policy (`SECURITY.md`)

```markdown
# Security Policy

Please report vulnerabilities privately to <security@example.com>.
Do not open a public issue for a live vulnerability.

Include:
- affected URL/commit,
- reproduction steps,
- impact,
- suggested fix (if any).

We aim to acknowledge within 72 hours and fix critical issues promptly.
Do not test against real user data or third-party systems without permission.
```

---

## 6. GitHub release notes (v1.0.0)

```markdown
# PhishGuard v1.0.0

PhishGuard is a free, explainable phishing-triage app for the public.

## Highlights
- URL analysis: lexical tricks, DNS, TLS, RDAP, opt-in threat intelligence.
- Email analysis: headers, SPF/DKIM/DMARC, links, HTML forms, attachments.
- QR decoding with destination preview.
- Static file analysis: executables, macros, PDF actions, archives, scripts.
- Social-media scam-language triage.
- Transparent 0–100 score with evidence and recommended actions.
- JSON and Markdown reports.
- Privacy-first: in-memory processing, no attachment execution, no page browsing.

## Security
- SSRF guard for DNS/TLS checks.
- Upload and rate limits.
- Server-side secrets.
- No raw HTML rendering of user content.

## Known limitations
- Static analysis only; no sandbox detonation.
- Social analysis is text-only.
- Email authentication is parsed from headers + DMARC DNS, not a full independent SPF/DKIM verification.
- Free-tier intel quotas can degrade coverage.

## Try it
<public URL>

## Feedback
Open an issue: <repo>/issues
```

---

## 7. LinkedIn / X launch post

```text
I built PhishGuard — a free, explainable phishing-triage app.

Most people are asked to trust a link, QR code, email, or attachment with no easy way
to check it. PhishGuard gives one workflow for all five:

🔗 URL — lookalikes, shorteners, DNS, TLS, domain age
📧 Email — Reply-To spoofing, SPF/DKIM/DMARC, forms, links, attachments
🔳 QR — decode locally, preview the destination
📎 File — executables, macros, PDF actions, archive tricks
💬 Social — crypto/prize/job scam language + shared links

Every result is explainable: a 0–100 score, individual signals with evidence, and a
recommended next action. No attachment execution. No page browsing. No storage of
your uploads.

It is defensive-only and built for the public, not just analysts.

Try it: <URL>
Code: <repo>

Feedback welcome — especially false positives/negatives.

#cybersecurity #phishing #infosec #python #streamlit #buildinpublic
```

---

## 8. Demo script (3 minutes)

1. **Intro (15s):** “PhishGuard is a free phishing-triage app for five input types.”
2. **URL (40s):** paste `http://paypa1.com/verify-account/login`; show lookalike, credential keywords, no HTTPS; explain the score.
3. **Email (40s):** upload a sanitized `.eml`; show Reply-To mismatch, SPF/DMARC failure, password form, link mismatch.
4. **QR (30s):** upload a QR that decodes to a suspicious URL; show the destination preview.
5. **File (30s):** upload `invoice.pdf.exe`; show executable + double extension; emphasize no execution.
6. **Social (20s):** paste a crypto/Telegram pitch; show language + link signals.
7. **Close (15s):** show JSON report, privacy note, limitations, GitHub link.

---

## 9. Beta feedback questions

1. What were you trying to check?
2. Was the verdict clear? Why or why not?
3. Which signal was most useful?
4. Which signal was confusing or seemed wrong?
5. Did you trust the result? Why?
6. Did it work on your phone?
7. What would make you use it again?
8. Did you notice anything about privacy or data handling?
9. How long did the analysis take?
10. What one thing should be fixed before launch?

---

## 10. Portfolio case-study outline

```markdown
# PhishGuard — case study

## Problem
People cannot easily tell whether a link, email, QR code, attachment, or social
message is a phishing attempt.

## Constraints
- Public users, no accounts.
- Sensitive uploads.
- No budget for paid APIs.
- Must not become an SSRF proxy or malware sandbox.

## Solution
A Streamlit modular monolith with five analyzers, a transparent scoring engine,
opt-in threat intelligence, and in-memory processing.

## Key decisions
- Rule-based before ML (explainability, no labels).
- No page fetch (SSRF safety).
- Static file analysis (safe deployment).
- Intel opt-in (privacy + quota).
- One result schema (consistent UX).

## Security
SSRF guard, upload/rate limits, no execution, no storage, server-side secrets,
XSS-safe rendering.

## Results
<analyses, beta users, false-positive fixes, latency>

## What I learned
<detection engineering, public-app security, privacy, UX>

## Next
PDF reports, .msg support, OCR, ML evaluation, custom domain.
```
