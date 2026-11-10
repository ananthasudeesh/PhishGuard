# PhishGuard — Master Build Guide

> **Project:** PhishGuard  
> **Goal:** a public, privacy-first web app that triages phishing across email, URLs, QR codes, files/attachments, and social-media messages.  
> **Audience:** general public, students, small businesses, and junior SOC analysts.  
> **Build style:** 2–4 focused hours per day for 30 days, with a deployable increment every week.

This is the top-level guide. Detailed companion documents:

- [`01-30-DAY-ROADMAP.md`](01-30-DAY-ROADMAP.md) — exact daily tasks, commands, acceptance criteria, commit messages.
- [`02-ARCHITECTURE.md`](02-ARCHITECTURE.md) — modules, data flow, interfaces, future API.
- [`03-SECURITY-PRIVACY.md`](03-SECURITY-PRIVACY.md) — threat model, SSRF, upload safety, privacy policy, legal.
- [`04-DEPLOYMENT.md`](04-DEPLOYMENT.md) — GitHub, Streamlit Cloud, secrets, CI, custom domain, rollback.
- [`05-TESTING.md`](05-TESTING.md) — test strategy, fixtures, CI, security tests.
- [`06-API-SETUP.md`](06-API-SETUP.md) — VirusTotal, Safe Browsing, urlscan, RDAP, quotas.
- [`07-DAY-01-VERIFICATION.md`](07-DAY-01-VERIFICATION.md) — finish/verify Day 1.
- [`08-LAUNCH-TEMPLATES.md`](08-LAUNCH-TEMPLATES.md) — README, privacy policy, ToS, disclaimer, launch post.

---

## 1. What PhishGuard is — and is not

### One-sentence pitch

**PhishGuard is a free, explainable phishing-triage web app that checks a suspicious email, link, QR code, attachment, or social-media message and tells the user what looks risky and what to do next.**

### The problem

People are asked to make trust decisions constantly:

- “Is this DHL delivery link real?”
- “Is this QR code on the parking meter safe?”
- “Is this ‘HR’ attachment a macro virus?”
- “Is this Instagram investment offer a scam?”

Existing tools are fragmented: URL scanners, email header analyzers, QR decoders, and malware sandboxes live in different places. Most are built for analysts, not the public.

### The product promise

One place, five input types, one consistent report:

```text
Input → local checks → optional intel → risk score → evidence → action
```

### Non-goals (write these down)

PhishGuard will **not**:

- create, host, or send phishing pages,
- collect credentials,
- execute attachments or detonate malware,
- automatically browse suspicious pages,
- scrape private social-media accounts or bypass login walls,
- claim that a “clean” result is a guarantee,
- replace an email gateway, EDR, or SOC.

This boundary protects users, keeps the project legal, and makes the public deployment much easier to secure.

---

## 2. Users and user stories

### Primary users

| User | Need | Success looks like |
| --- | --- | --- |
| General public | “Is this link/message safe?” | A clear verdict and a next action in under 30 seconds |
| Student / job seeker | Check internship, scholarship, and job offers | Scam language and fake domains explained |
| Small business owner | Check invoices, attachments, and supplier emails | Attachment and header risks without a SOC |
| Junior SOC analyst | Triage a reported email quickly | Evidence table and downloadable report |
| Cybersecurity student | Learn detection engineering | Transparent, testable signals |

### MVP user stories

1. As a user, I can paste a URL and get a verdict with evidence.
2. As a user, I can upload an `.eml` and see sender, authentication, link, and attachment risks.
3. As a user, I can upload a QR image and see the decoded destination before opening it.
4. As a user, I can upload an attachment and learn whether it is executable, macro-enabled, or archive-based.
5. As a user, I can paste a social-media message and see scam-language and link risks.
6. As a user, I can download a JSON/Markdown report.
7. As a privacy-conscious user, I can see that my upload is not stored and can opt out of third-party intelligence.
8. As a public user, I cannot accidentally trigger unlimited scans or huge uploads.

### Acceptance criteria for the MVP

- All five analyzers return the same `AnalysisResult` shape.
- Every score is explainable by visible signals.
- No raw email/file is written to disk.
- No attachment is executed.
- No page is fetched/rendered by the public app.
- Upload limit and per-session rate limit are enforced.
- Secrets are never exposed to the browser.
- Unit tests cover scoring and each analyzer’s core heuristics.
- The app is publicly reachable and has a privacy/disclaimer section.

---

## 3. Scope: MVP vs later

### P0 — must ship for public MVP

- URL analyzer: lexical, DNS, TLS, RDAP, optional intel.
- Email `.eml` analyzer: headers, auth results, body links, HTML forms, attachment metadata.
- QR decoder → URL analyzer.
- File analyzer: hash, magic, extension, macros, PDF, archives, scripts, optional hash reputation.
- Social text analyzer: language patterns + shared links.
- Transparent scoring + recommendations.
- JSON/Markdown report.
- Rate limit, size limit, privacy notice, disclaimer.
- GitHub repo + Streamlit deployment + tests.

### P1 — first post-launch improvements

- PDF report with branding.
- Screenshot/OCR for social-media screenshots.
- Outlook `.msg` support.
- Domain reputation history/caching across users (privacy-preserving).
- Turnstile/CAPTCHA.
- Custom domain.
- More languages (Malayalam/Hindi/English) for scam-language patterns.
- Shareable redacted report link.

### P2 — later / research

- FastAPI backend + Redis cache + queue.
- ML URL classifier trained on PhishTank/OpenPhish/URLhaus + Tranco.
- Sandbox integration for detonation (with strict isolation and consent).
- Browser extension.
- Organisation accounts and team dashboards.
- Email gateway integration.

> Keep P0 small. A public tool that does five things reliably is better than a half-finished platform.

---

## 4. Technology choices

| Layer | Choice | Why |
| --- | --- | --- |
| UI | Streamlit | Fastest path to a public data app; free Community Cloud; easy file uploads |
| Language | Python 3.11/3.12 | Email, DNS, file, and security libraries are mature |
| Email parsing | stdlib `email` + BeautifulSoup | No external service; safe text extraction |
| DNS | `dnspython` | A/AAAA/MX/NS/TXT/DMARC lookups |
| Domain age | RDAP over HTTPS | No WHOIS port/rate-limit pain |
| TLS | stdlib `ssl` + pinned public IP | Certificate check without fetching the page |
| QR | OpenCV headless | Local decoding, no upload to a QR API |
| Files | stdlib `zipfile`, `olefile`, magic-byte detection | Static analysis without execution |
| Intel | VirusTotal, Google Safe Browsing, urlscan.io | Optional reputation layer |
| Tests | pytest | Simple, fast, CI-friendly |
| CI | GitHub Actions | Free for public repos |
| Hosting | Streamlit Community Cloud | Free public deployment, secrets support |
| Future API | FastAPI + Redis | Only when the monolith is genuinely limiting |

### Why not a full React + FastAPI stack on Day 1?

Because the hard part is detection quality, public trust, and abuse resistance — not the UI framework. A modular monolith lets you ship, learn, and then split the backend when you have real traffic.

---

## 5. Architecture at a glance

```text
┌──────────────────────────────────────────────────────────────┐
│                        Streamlit UI                          │
│  URL │ Email │ QR │ File │ Social │ report download          │
└───────────────┬──────────────────────────────────────────────┘
                │
        ┌───────▼────────┐
        │  Orchestration │  rate limit, size limit, intel opt-in
        └───────┬────────┘
                │
   ┌────────────┼─────────────┬──────────────┬──────────────┐
   ▼            ▼             ▼              ▼              ▼
 URL          Email          QR            File          Social
 analyzer     analyzer      analyzer       analyzer      analyzer
   │            │             │              │              │
   └────────────┴──────┬──────┴──────────────┴──────────────┘
                       ▼
              ┌─────────────────┐
              │ scoring engine  │  weight × confidence, capped
              └────────┬────────┘
                       ▼
          ┌──────────────────────────┐
          │ AnalysisResult           │
          │ score / verdict / signals│
          │ evidence / actions       │
          └──────────────────────────┘
```

### Module responsibilities

| Module | Responsibility |
| --- | --- |
| `app.py` | UI, tabs, upload limits, rate limit, rendering, downloads |
| `models.py` | `Signal`, `AnalysisResult`, `Severity`, `Verdict` |
| `scoring.py` | dedupe, score, verdict thresholds, confidence, recommendations |
| `utils.py` | URL normalization, SSRF-safe DNS/TLS, RDAP, magic bytes, hashing |
| `intel.py` | optional VirusTotal/GSB/urlscan clients, TTL cache |
| `analyzers/url.py` | lexical + network + intel signals |
| `analyzers/email.py` | headers, auth, body, links, attachments |
| `analyzers/qr.py` | decode + URL analysis |
| `analyzers/file.py` | static file/attachment heuristics |
| `analyzers/social.py` | scam-language patterns + shared links |

### Data flow rules

1. Validate size and type **before** parsing.
2. Parse in memory only.
3. Never execute or extract to disk.
4. Run local checks first; intel only if the user opted in.
5. Normalize every analyzer into `AnalysisResult`.
6. Render evidence as data, not raw HTML.
7. Delete references when the request ends.

More detail: [`02-ARCHITECTURE.md`](02-ARCHITECTURE.md).

---

## 6. Detection design

### The core idea: explainable signals, not a black box

A signal is a small, testable observation:

```python
Signal(
    id="url.brand_lookalike",
    title="Domain closely resembles a known brand",
    severity=Severity.HIGH,
    category="url",
    description="The registered domain looks similar to 'paypal'.",
    evidence="paypa1.com",
    weight=35,
)
```

The score is the capped sum of `weight × confidence`. This makes every result auditable and easy to improve.

### Signal categories

| Category | Examples |
| --- | --- |
| `url` | punycode, lookalike brand, shortener, raw IP, suspicious TLD, new domain, invalid TLS |
| `email` | Reply-To mismatch, display-name spoof, SPF/DKIM/DMARC failure, no DMARC |
| `credentials` | password form, OTP/password request |
| `attachment` | macro, executable, double extension, archive bomb |
| `qr` | decoded destination, payment text |
| `social` | crypto pitch, prize, urgency, off-platform pressure |
| `intel` | VirusTotal detections, Safe Browsing match, urlscan malicious history |

### Weighting guidance

- **Critical (70–90):** confirmed malicious intel, executable payload, private-IP SSRF target.
- **High (25–50):** strong impersonation, auth failure, macro, lookalike domain.
- **Medium (10–24):** shortener, new domain, password form, urgency.
- **Low (1–9):** long URL, no HTTPS, many hyphens.
- **Info (0):** “checked”, “clean”, “decoded”.

Do not let many weak signals add up to “malicious” without at least one strong signal. The current `verdict_for()` also requires a critical signal to reach 50 before calling something malicious.

### Avoid false-positive traps

- `microsoftonline.com`, `googleusercontent.com`, and `amazonaws.com` are legitimate but often abused. Treat brand tokens as **low/medium**, not automatic malice.
- A valid TLS certificate is **not** a trust signal; phishing sites use HTTPS.
- URL shorteners are common in legitimate marketing. Weight them as medium, not high.
- Do not score grammar, spelling, or non-native English; it is biased and unreliable.
- Do not claim “0 detections = safe”.

### Threat-intelligence policy

- Intel is **opt-in** per analysis.
- Send only the URL/domain or SHA-256 hash — never raw email bodies or files.
- Cache results for 15 minutes to protect free-tier quotas.
- Treat API errors as “unknown”, not “clean”.
- Show the source and evidence for every intel signal.
- Keep keys server-side in Streamlit secrets.

More: [`06-API-SETUP.md`](06-API-SETUP.md).

---

## 7. Public deployment model

### MVP hosting

- GitHub public repository.
- Streamlit Community Cloud, entrypoint `app.py`.
- Secrets in the Streamlit dashboard.
- Optional custom domain via Streamlit Cloud settings / DNS.
- GitHub Actions for tests on every push.

### Why this is appropriate

- Free and public.
- No server to patch.
- Secrets are not shipped to the browser.
- Streamlit handles TLS and basic isolation.
- Good enough for a portfolio/public beta.

### What it does not give you

- Fine-grained WAF/rate limiting.
- Persistent cache or database.
- Long-running background jobs.
- Strong per-IP abuse controls.

For a public launch, add application-level limits (already in the MVP) and consider Cloudflare Turnstile or a small FastAPI gateway if abuse appears.

Full checklist: [`04-DEPLOYMENT.md`](04-DEPLOYMENT.md).

---

## 8. Security, privacy, and legal

This is not optional for a public phishing tool. Users will upload real emails and files.

### Minimum controls

- In-memory processing; no upload persistence.
- 10 MB upload limit (server + app).
- 20 analyses per session per hour.
- No attachment execution.
- No page fetch/render.
- SSRF guard: resolve host, reject private/reserved IPs, pin the TLS connection to a validated public IP.
- Zip-bomb and path-traversal checks.
- No raw HTML rendering of user content.
- Secrets in environment/secrets, never in Git.
- Redact logs; do not log email bodies or filenames.
- Clear privacy notice and disclaimer.
- Report an issue / security contact.

### Legal pages you need

- Privacy Policy (what is processed, for how long, third parties, rights).
- Terms of Use (acceptable use, no warranty, limitation of liability).
- Disclaimer (indicators, not proof).
- Acceptable Use / Prohibited Use (no phishing creation, no unauthorized analysis).
- Security contact / responsible disclosure.

Templates: [`08-LAUNCH-TEMPLATES.md`](08-LAUNCH-TEMPLATES.md). Threat model: [`03-SECURITY-PRIVACY.md`](03-SECURITY-PRIVACY.md).

### Data-protection note

If you are in India, review the Digital Personal Data Protection Act, 2023. If you serve EU/UK users, review GDPR/UK GDPR. Even if you store nothing, you still need a clear notice because users upload personal data. Do not assume “it is just a student project” removes those duties.

---

## 9. Quality bar and testing

### Test pyramid

- **Unit:** scoring, URL lexical rules, email header parsing, file signatures, social patterns, QR decode.
- **Integration:** `.eml` → URL analyzer → score; QR → URL analyzer.
- **UI smoke:** Streamlit `AppTest` renders all tabs without exceptions.
- **Security:** SSRF guard, zip bomb, path traversal, oversized upload, XSS-safe rendering.
- **Manual:** real sanitized samples, mobile browser, slow network, API failure.

### Definition of done for every day

- Code runs locally.
- New behaviour has at least one test or a documented manual check.
- `PYTHONPATH=src pytest -q` passes.
- No secrets or real victim data committed.
- README/docs updated if behaviour changed.
- One clear commit with a meaningful message.
- Deployed app still works (at least at the end of each week).

Full strategy: [`05-TESTING.md`](05-TESTING.md).

---

## 10. Metrics and launch

### Product metrics

- Analyses per day.
- Verdict distribution (malicious/suspicious/likely safe/unknown).
- Most common input type.
- Report download rate.
- Error rate by analyzer.
- Median analysis time.
- API quota/error rate.
- Repeat usage.

### Quality metrics

- False-positive reports from beta users.
- False-negative reports (the most important).
- Test coverage of scoring and analyzers.
- Percentage of signals with evidence.
- Time to add a new indicator.

### Launch checklist

- [ ] Public GitHub repo with README, LICENSE, screenshots.
- [ ] Streamlit app deployed and reachable.
- [ ] Secrets configured; no keys in Git history.
- [ ] Privacy, ToS, disclaimer, and security contact pages.
- [ ] Upload/rate limits verified.
- [ ] Test suite green.
- [ ] 10 beta users tried all five analyzers.
- [ ] Demo video/GIF and 3–5 screenshots.
- [ ] Launch post with a clear “defensive use” statement.
- [ ] Monitoring: check Streamlit logs and API quotas daily for the first week.
- [ ] Rollback plan: previous working commit + redeploy.

---

## 11. Daily workflow (2–4 hours)

Use the same rhythm every day:

1. **10 min — review:** read yesterday’s commit, open the app, run tests.
2. **60–120 min — build:** implement the day’s smallest useful increment.
3. **30 min — test:** add/update tests; try one malicious and one benign sample.
4. **20 min — document:** update README/docstring/roadmap.
5. **15 min — ship:** commit, push, wait for CI, redeploy if needed.
6. **5 min — journal:** what worked, what broke, tomorrow’s first task.

### Commit message pattern

```text
feat(url): add punycode and lookalike-brand signals
test(email): cover Reply-To mismatch and SPF failure
fix(file): prevent zip-bomb metadata blow-up
docs(deploy): add Streamlit secrets checklist
```

### If you only have 45 minutes

- 5 min review.
- 25 min one small signal or test.
- 10 min verify.
- 5 min commit.

Never skip the commit. A daily green commit is the project’s heartbeat.

---

## 12. Day 1 verification (important)

The local repository at `~/PhishGuard` currently contains only the initial scaffold: no commits, no remote, an empty `src/`, and an empty `requirements.txt`. If your GitHub repo and public app are already live, treat this as a verification checklist. If not, fix it before Day 2.

```bash
cd ~/PhishGuard
git status
git remote -v
git log --oneline -5
```

Expected: a `main` branch, a GitHub remote, at least one commit, and a public app URL.

If any are missing, see [`07-DAY-01-VERIFICATION.md`](07-DAY-01-VERIFICATION.md) for the exact recovery commands.

---

## 13. 30-day roadmap summary

| Week | Theme | Outcome |
| --- | --- | --- |
| 1 | Foundation + URL engine | Public app checks URLs with explainable signals and intel |
| 2 | Email | `.eml` upload, headers/auth, links, attachments, email report |
| 3 | QR + social + files + UX | All five input types, better reports, mobile-friendly UI |
| 4 | Hardening + launch | Abuse controls, security review, privacy/legal, beta, public launch |

Daily detail: [`01-30-DAY-ROADMAP.md`](01-30-DAY-ROADMAP.md).

---

## 14. Common mistakes to avoid

1. **Building the UI before the detection logic.** The score and evidence are the product.
2. **Adding an ML model on Day 3.** You need clean labels, evaluation, and explainability first.
3. **Fetching every URL to “check” it.** That turns your app into an SSRF proxy and a malware exposure.
4. **Storing uploads “for debugging”.** A public phishing tool must not become a victim-data archive.
5. **Putting API keys in the repo.** Even a deleted key is compromised.
6. **Claiming “safe”.** Use “no strong indicators found” and explain limits.
7. **Ignoring mobile.** Most users will open the link on a phone.
8. **Skipping the privacy page.** Users are uploading real personal data.
9. **Adding too many weak signals.** It creates false positives and erodes trust.
10. **Not testing benign samples.** A tool that flags everything is useless.

---

## 15. How to present this project

### Resume bullet

> Built and deployed PhishGuard, a public phishing-triage web app that analyzes email headers, URLs, QR codes, attachments, and social-media messages using transparent rule-based detection, DNS/TLS/RDAP checks, and optional threat intelligence; implemented SSRF-safe URL handling, in-memory file analysis, rate limits, and a pytest/CI pipeline.

### Demo script (3 minutes)

1. Show the public URL and the five tabs.
2. Paste a lookalike URL (`http://paypa1.com/verify`) and explain the signals.
3. Upload a sanitized `.eml` with Reply-To mismatch and SPF fail.
4. Upload a QR code that decodes to a suspicious domain.
5. Upload a fake `invoice.pdf.exe` and show the executable/double-extension signals.
6. Show the JSON report and the privacy note.
7. End with limitations: triage, not proof; no execution; no storage.

### What to say about the score

> “Every point is traceable to a signal. I can show the user exactly why the score is 50, and I can add or tune a rule with a test. That is more useful for public trust than a black-box model.”

---

## 16. Next action

1. Run the Day 1 verification.
2. Open the 30-day roadmap.
3. Do **Day 2** today: repository hygiene, CI, and a clean baseline commit.
4. At the end of each week, deploy and demo — do not wait until Day 30.

You do not need permission to start. Open the roadmap, pick today’s task, and ship one small, tested increment.
