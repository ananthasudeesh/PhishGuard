# PhishGuard — 30-Day Build Roadmap

> **Time budget:** 2–4 hours per day.  
> **Rule:** one deployable, tested increment per day.  
> **Starting point:** Day 1 (environment + public GitHub + public app).  
> **Reference implementation:** the repository now contains a working MVP in `app.py`, `src/phishguard/`, and `tests/`. You can either rebuild it day by day or use it as the answer key while you harden and extend it.

Each day has:

- **Goal** — the one thing that must work.
- **Tasks** — concrete steps.
- **Files** — where the work lives.
- **Verify** — how you know it is done.
- **Commit** — a suggested message.
- **Stretch** — optional if you have time.

---

## Week 1 — Foundation, URL engine, and public deployment

### Day 1 — Environment, public GitHub, public app

**Goal:** a public repository and a public “hello, PhishGuard” Streamlit app.

**Tasks**
1. Verify Python, pip, Git, VS Code, and venv.
2. Create the project structure and `.gitignore`.
3. Create a public GitHub repository named `PhishGuard`.
4. Push the initial scaffold.
5. Deploy `app.py` on Streamlit Community Cloud.
6. Add the public URL to the README.

**Files:** `README.md`, `.gitignore`, `requirements.txt`, `LICENSE`, `app.py`.

**Verify**
```bash
python3 --version
git remote -v
git log --oneline -1
curl -I https://<your-app>.streamlit.app
```

**Commit:** `chore: initial PhishGuard scaffold and public deployment`

**If your local repo has no commits/remote yet:** follow [`07-DAY-01-VERIFICATION.md`](07-DAY-01-VERIFICATION.md) before continuing.

---

### Day 2 — Repository hygiene, CI, and a clean baseline

**Goal:** every push runs tests, and the repo is safe to make public.

**Tasks**
1. Add `requirements.txt` with runtime and dev dependencies.
2. Add `.streamlit/config.toml` with upload limits and theme.
3. Add `.env.example`; confirm `.env` is ignored.
4. Add a GitHub Actions workflow that runs `pytest`.
5. Add a `LICENSE` (MIT) and a security note in the README.
6. Make the first clean commit on `main`.

**Files:** `.github/workflows/tests.yml`, `requirements.txt`, `.streamlit/config.toml`, `.env.example`, `.gitignore`.

**Commands**
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
PYTHONPATH=src pytest -q
git add .
git commit -m "chore: add project hygiene and CI"
git push origin main
```

**Verify:** the Actions tab is green; `git status` is clean; no `.env` or keys are tracked.

**Commit:** `chore(ci): run pytest on every push`

**Stretch:** add a `Makefile` with `make test`, `make run`, `make lint`.

---

### Day 3 — Data models and the scoring engine

**Goal:** one result shape and one transparent scoring rule for every analyzer.

**Tasks**
1. Create `Signal`, `AnalysisResult`, `Severity`, and `Verdict`.
2. Implement score = capped sum of `weight × confidence`.
3. Deduplicate repeated signal IDs, keeping the strongest.
4. Implement verdict thresholds: 70+ malicious, 35–69 suspicious, <35 likely safe, no data unknown.
5. Add unit tests for caps, deduplication, thresholds, and recommendations.

**Files:** `src/phishguard/models.py`, `src/phishguard/scoring.py`, `tests/test_scoring.py`.

**Verify**
```bash
PYTHONPATH=src pytest tests/test_scoring.py -q
```

**Commit:** `feat(core): add explainable signal and scoring models`

**Stretch:** add a `to_markdown()` report method.

---

### Day 4 — URL lexical analyzer

**Goal:** catch obvious URL tricks without any network calls.

**Tasks**
1. Normalize/refang URLs (`hxxp`, `[.]`, missing scheme).
2. Detect raw IPs, private IPs, `@` credentials, punycode, non-ASCII hosts.
3. Detect suspicious TLDs, shorteners, unusual ports, no HTTPS, long URLs.
4. Detect lookalike brands and brand names in subdomains.
5. Detect credential/payment keywords and executable downloads.
6. Add tests with malicious and benign URLs.

**Files:** `src/phishguard/utils.py`, `src/phishguard/analyzers/url.py`, `tests/test_url.py`.

**Verify**
```bash
PYTHONPATH=src pytest tests/test_url.py -q
```

**Commit:** `feat(url): add lexical phishing signals`

**Stretch:** add homograph/leet-speak normalization (`paypa1` → `paypal`).

---

### Day 5 — DNS, TLS, RDAP, and the SSRF guard

**Goal:** enrich URL analysis without becoming a proxy for internal networks.

**Tasks**
1. Resolve A/AAAA/MX/NS/TXT with short timeouts.
2. Reject private, loopback, link-local, multicast, and reserved IPs.
3. Connect to a validated public IP while keeping the original hostname for SNI.
4. Check certificate validity and expiry.
5. Look up domain age via RDAP; flag domains under 30/90 days.
6. Add tests for the private-IP path; mock network calls.

**Files:** `src/phishguard/utils.py`, `src/phishguard/analyzers/url.py`, `tests/test_url.py`.

**Verify:** `http://192.168.1.1/login` is critical; a normal public URL still resolves; no page is fetched.

**Commit:** `feat(url): add DNS, TLS, RDAP, and SSRF-safe checks`

**Stretch:** add a DNS timeout budget so the UI never hangs for more than ~8 seconds.

---

### Day 6 — Optional threat intelligence

**Goal:** add reputation data without leaking user content or blowing free-tier quotas.

**Tasks**
1. Add VirusTotal URL and file-hash clients.
2. Add Google Safe Browsing URL lookup.
3. Add urlscan.io domain search.
4. Cache results for 15 minutes.
5. Add an opt-in checkbox and a clear “only URLs/hashes are sent” note.
6. Treat errors as unknown, not clean.
7. Test with keys absent (the app must still work).

**Files:** `src/phishguard/intel.py`, `src/phishguard/analyzers/url.py`, `src/phishguard/analyzers/file.py`, `tests/`.

**Verify:** with no keys, the app works and shows “not configured”; with a key, a known bad URL produces an intel signal.

**Commit:** `feat(intel): add optional VirusTotal, Safe Browsing, and urlscan`

**Stretch:** add a quota-aware “intel disabled for this session” state.

---

### Day 7 — URL UI, report, deploy, weekly review

**Goal:** a public URL analyzer with a downloadable report.

**Tasks**
1. Build the URL tab: input, opt-in, analyze, result card.
2. Show score, verdict, confidence, evidence table, and actions.
3. Add JSON and Markdown downloads.
4. Add a privacy/limits sidebar.
5. Deploy and test on mobile.
6. Write a short weekly review: what works, what is noisy, what to fix.

**Files:** `app.py`, `README.md`, `documentation/`.

**Verify:** a malicious URL, a benign URL, and a shortener all produce sensible results; the app is reachable publicly.

**Commit:** `feat(ui): add URL analysis tab and report downloads`

**Stretch:** add 3 screenshots to `screenshots/`.

---

## Week 2 — Email analysis

### Day 8 — `.eml` parser and metadata

**Goal:** safely extract headers, body text, and attachment metadata.

**Tasks**
1. Parse bytes with `email.parser.BytesParser(policy=default)`.
2. Extract From, Reply-To, Return-Path, Sender, Subject, Date, Message-ID.
3. Extract text/plain and text/html bodies; do not render HTML.
4. Extract attachment names, types, sizes, and hashes.
5. Add size limits and malformed-message handling.
6. Add a benign and a phishing `.eml` fixture.

**Files:** `src/phishguard/analyzers/email.py`, `tests/test_email.py`, `samples/`.

**Verify**
```bash
PYTHONPATH=src pytest tests/test_email.py -q
```

**Commit:** `feat(email): parse headers, bodies, and attachment metadata`

**Stretch:** add RFC 2047 filename decoding tests.

---

### Day 9 — Header and authentication analysis

**Goal:** explain sender identity and SPF/DKIM/DMARC failures.

**Tasks**
1. Parse `Authentication-Results` and `Received-SPF`.
2. Flag SPF/DKIM/DMARC fail/softfail/permerror.
3. Look up `_dmarc.<domain>` TXT and flag missing/p=none.
4. Detect From/Reply-To/Return-Path/Sender mismatches.
5. Detect display-name brand spoofing and lookalike sender domains.
6. Add tests for each mismatch.

**Files:** `src/phishguard/analyzers/email.py`, `tests/test_email.py`.

**Verify:** the phishing fixture produces auth, Reply-To, and display-name signals; the benign fixture does not.

**Commit:** `feat(email): add header and authentication signals`

**Stretch:** add a “header chain” viewer with the first/last Received hop.

---

### Day 10 — Body, HTML forms, and link extraction

**Goal:** catch credential forms and misleading link text.

**Tasks**
1. Extract URLs from text and HTML.
2. Detect `<input type=password>` forms.
3. Compare visible link text with the actual href domain.
4. Detect brand names in text that point to a non-brand domain.
5. Run the URL analyzer on the top 5 unique links.
6. Add tests for form and link-text mismatch.

**Files:** `src/phishguard/analyzers/email.py`, `src/phishguard/analyzers/url.py`, `tests/test_email.py`.

**Verify:** a PayPal-labelled link to `paypa1.com` produces both a link mismatch and a URL signal.

**Commit:** `feat(email): detect credential forms and deceptive links`

**Stretch:** add a “links found” table to the email report.

---

### Day 11 — Attachment static analysis

**Goal:** inspect attachments without executing or extracting them.

**Tasks**
1. Compute SHA-256/MD5/SHA-1.
2. Detect executables, scripts, LNK, ISO, OneNote, and RTF objects.
3. Detect OLE macros and OOXML `vbaProject.bin`.
4. Detect PDF JavaScript, launch actions, and embedded files.
5. Detect archive bombs, path traversal, encrypted archives, and executable entries.
6. Add tests for `invoice.pdf.exe`, macro DOCX, and a traversal ZIP.

**Files:** `src/phishguard/analyzers/file.py`, `tests/test_file.py`.

**Verify:** all three test cases produce the expected signals; no file is written to disk.

**Commit:** `feat(file): add static attachment analysis`

**Stretch:** add a per-attachment summary to the email metadata.

---

### Day 12 — Email scoring and report

**Goal:** turn email signals into a clear verdict and action list.

**Tasks**
1. Merge URL and attachment signals into the email result without double-counting.
2. Scale nested URL/attachment signals (for example 50–60% weight).
3. Add email-specific recommendations.
4. Add a “top 3 things to check” summary.
5. Add a JSON/Markdown report test.
6. Review false-positive risk on a normal newsletter.

**Files:** `src/phishguard/analyzers/email.py`, `src/phishguard/scoring.py`, `tests/`.

**Verify:** a normal newsletter stays below 35; the phishing fixture is suspicious/malicious.

**Commit:** `feat(email): aggregate nested signals and recommendations`

**Stretch:** add a `severity_counts` field to the result.

---

### Day 13 — Email UI, samples, and docs

**Goal:** a usable email tab with safe upload handling.

**Tasks**
1. Add `.eml` upload with a 10 MB limit.
2. Show sender, subject, auth results, links, and attachments.
3. Show the evidence table and downloads.
4. Add 3 sanitized samples to `samples/` (no real victim data).
5. Update the README with an email walkthrough.
6. Test on mobile.

**Files:** `app.py`, `samples/`, `README.md`.

**Verify:** upload a sample, get a report, download JSON; an oversized file is rejected.

**Commit:** `feat(ui): add email investigation tab`

**Stretch:** add a “copy redacted summary” button.

---

### Day 14 — Deploy, docs, weekly review

**Goal:** email analysis is live and documented.

**Tasks**
1. Deploy the new version.
2. Add a 60-second demo GIF of the email flow.
3. Update the architecture and privacy docs.
4. Run the full test suite and CI.
5. Collect 3 pieces of feedback from a friend/classmate.
6. Write next week’s priorities.

**Verify:** public app handles all email cases; CI green; docs match behaviour.

**Commit:** `docs: add email walkthrough and deploy notes`

**Stretch:** add a “known limitations” section for email auth parsing.

---

## Week 3 — QR, social media, files, and UX

### Day 15 — QR decode and URL pipeline

**Goal:** decode a QR image locally and analyze its destination.

**Tasks**
1. Decode with OpenCV `QRCodeDetector` (single and multi).
2. Handle invalid images and no-QR images gracefully.
3. Preview the decoded value before opening anything.
4. Run the URL analyzer on decoded URLs.
5. Detect payment/credential text in non-URL QR content.
6. Add a generated-QR test.

**Files:** `src/phishguard/analyzers/qr.py`, `tests/test_qr.py`, `app.py`.

**Verify:** a QR for `http://paypa1.com/login` is suspicious; a benign QR is not malicious.

**Commit:** `feat(qr): decode QR codes and analyze destinations`

**Stretch:** add a “copy decoded text” button.

---

### Day 16 — Social-media message analyzer

**Goal:** catch common social scams without platform APIs.

**Tasks**
1. Add pattern groups: crypto/investment, prize, urgency, credentials, impersonation, off-platform, job scam, too-good-to-be-true.
2. Detect brand + “official/support” impersonation.
3. Extract and analyze shared links.
4. Add a platform selector and text area.
5. Add tests for scam and benign messages.
6. Avoid grammar/spelling scoring.

**Files:** `src/phishguard/analyzers/social.py`, `tests/test_social.py`, `app.py`.

**Verify:** a crypto/Telegram pitch is suspicious; “coffee at 5?” is likely safe.

**Commit:** `feat(social): add scam-language and link triage`

**Stretch:** add Malayalam/Hindi scam keywords if you can validate them with native speakers.

---

### Day 17 — File analyzer hardening

**Goal:** make the file analyzer robust against hostile inputs.

**Tasks**
1. Cap archive entry count and uncompressed size before parsing.
2. Never extract to disk.
3. Handle malformed ZIP/OLE/PDF without crashing.
4. Add nested archive awareness (one level only).
5. Add password-protected and encrypted Office signals.
6. Add fuzz-ish tests with random bytes.

**Files:** `src/phishguard/analyzers/file.py`, `tests/test_file.py`.

**Verify:** random bytes, truncated ZIPs, and a 200 MB-claimed ZIP do not crash the app.

**Commit:** `fix(file): harden archive and malformed-input handling`

**Stretch:** add a “why this file is risky” plain-English summary.

---

### Day 18 — Unified pipeline and result UI

**Goal:** every analyzer uses the same result card and report.

**Tasks**
1. Refactor the UI to one `render_result()` component.
2. Ensure all analyzers return `AnalysisResult`.
3. Add a common severity/verdict color system.
4. Add “top signal” and “next action” to every report.
5. Add a smoke test that renders all five tabs.
6. Remove duplicated UI code.

**Files:** `app.py`, `src/phishguard/models.py`, `tests/`.

**Verify:** all tabs render without exceptions; every result has score, verdict, signals, actions, downloads.

**Commit:** `refactor(ui): unify result rendering across analyzers`

**Stretch:** add a compact “analyst mode” with raw metadata.

---

### Day 19 — Reports: JSON, Markdown, PDF

**Goal:** a report a non-technical user can share.

**Tasks**
1. Finalize the JSON schema and version it.
2. Improve the Markdown report (summary, evidence, actions, limitations).
3. Add a PDF report with reportlab or WeasyPrint.
4. Add a “redact target” option for screenshots/sharing.
5. Add a report-generation test.
6. Add a sample report to `reports/` (gitignored except `.gitkeep`).

**Files:** `src/phishguard/report.py`, `app.py`, `tests/`.

**Verify:** download all three formats; PDF opens and contains the verdict/evidence.

**Commit:** `feat(report): add JSON, Markdown, and PDF exports`

**Stretch:** add a QR code to the PDF that links to the public app.

---

### Day 20 — Public UX, accessibility, mobile

**Goal:** a tool a non-technical person can use on a phone.

**Tasks**
1. Test at 360 px width.
2. Increase tap targets and font sizes.
3. Add plain-language labels (“Paste a link”, not “URL lexical analysis”).
4. Add an example input for each tab.
5. Add an “empty state” and a “what happens to my data?” note.
6. Check color contrast and keyboard navigation.
7. Add a 3-step “How it works” section.

**Files:** `app.py`, `.streamlit/config.toml`.

**Verify:** all tabs usable on a phone; no horizontal scrolling; contrast passes a basic check.

**Commit:** `feat(ui): improve mobile, accessibility, and empty states`

**Stretch:** add a “report a false positive” link.

---

### Day 21 — Performance, caching, errors, weekly review

**Goal:** the app feels fast and fails gracefully.

**Tasks**
1. Measure p50/p95 analysis time for each analyzer.
2. Add timeouts to all network calls.
3. Cache intel results; do not cache raw uploads.
4. Add friendly error messages for timeouts, invalid files, and API failures.
5. Add a “partial result” note when intel is unavailable.
6. Run a 20-analysis smoke test.
7. Write the weekly review.

**Verify:** no request hangs for more than ~10 seconds; API failure still produces local signals.

**Commit:** `perf: add timeouts, caching, and graceful degradation`

**Stretch:** add a simple timing field to the result metadata.

---

## Week 4 — Hardening, legal, beta, and launch

### Day 22 — Abuse controls

**Goal:** prevent the public app from being used as a free scanning service.

**Tasks**
1. Enforce a per-session hourly limit.
2. Enforce server and app upload limits.
3. Add a simple challenge (Cloudflare Turnstile) or a queue if abuse appears.
4. Add a “too many requests” message.
5. Add a session reset control.
6. Document the limits in the UI.

**Files:** `app.py`, `documentation/03-SECURITY-PRIVACY.md`.

**Verify:** the 21st analysis in an hour is blocked; a 20 MB file is rejected before parsing.

**Commit:** `feat(security): add rate and upload limits`

**Stretch:** add per-IP limits via a small FastAPI gateway if Streamlit is not enough.

---

### Day 23 — Security review

**Goal:** find and fix the obvious public-app vulnerabilities.

**Tasks**
1. SSRF: verify private/reserved IP rejection, DNS rebinding assumptions, redirects not followed.
2. XSS: verify no user content is rendered with `unsafe_allow_html`.
3. File handling: zip bomb, path traversal, malformed archives, memory caps.
4. Secrets: scan Git history and logs.
5. Dependency audit: `pip-audit`.
6. Add a security checklist to the repo.
7. Fix at least the top 3 findings.

**Files:** `documentation/03-SECURITY-PRIVACY.md`, `SECURITY.md`.

**Verify:** private IP is blocked; no secrets in `git log`; `pip-audit` has no critical issues (or they are documented).

**Commit:** `fix(security): address SSRF, upload, and secret-handling findings`

**Stretch:** add a `SECURITY.md` responsible-disclosure policy.

---

### Day 24 — Privacy policy, terms, disclaimer

**Goal:** users know what happens to their data.

**Tasks**
1. Write a privacy policy with data categories, purpose, retention, third parties, and rights.
2. Write terms of use and acceptable-use rules.
3. Add a clear disclaimer: indicators, not proof.
4. Add a security contact.
5. Link all pages from the app sidebar and README.
6. Add a “last updated” date.

**Files:** `documentation/legal/`, `app.py`, `README.md`.

**Verify:** every page is reachable; the privacy text matches the actual code (no storage, opt-in intel).

**Commit:** `docs(legal): add privacy, terms, and acceptable-use pages`

**Stretch:** have a lawyer/DPO review if you expect significant public traffic.

---

### Day 25 — Observability and incident response

**Goal:** know when the app is broken or being abused.

**Tasks**
1. Add structured, redacted logs (no bodies, no filenames).
2. Track analysis count, errors, and latency.
3. Add a `/health`-style status section or a simple status page.
4. Document how to rotate API keys.
5. Document how to roll back a deployment.
6. Add an incident-response checklist for leaked keys or abuse.

**Files:** `documentation/04-DEPLOYMENT.md`, `documentation/03-SECURITY-PRIVACY.md`.

**Verify:** you can answer “is it up?”, “is it fast?”, “is a key failing?”, “how do I roll back?”.

**Commit:** `ops: add redacted logging and incident checklist`

**Stretch:** add uptime monitoring (UptimeRobot/Better Stack free tier).

---

### Day 26 — Test coverage and CI quality

**Goal:** confidence to change rules without breaking the app.

**Tasks**
1. Add tests for every analyzer’s happy path and one hostile input.
2. Add a Streamlit `AppTest` smoke test for all tabs.
3. Add coverage reporting (`pytest-cov`).
4. Add `ruff` for lint/format.
5. Add `mypy` (or pyright) for the core modules.
6. Make CI run tests + lint on every push.
7. Set a realistic coverage target (70–80%, not 100%).

**Files:** `.github/workflows/tests.yml`, `pyproject.toml`, `tests/`.

**Verify:** CI is green; a deliberately broken test fails CI; coverage report is published.

**Commit:** `test: raise coverage and add lint/type checks to CI`

**Stretch:** add a scheduled weekly dependency update.

---

### Day 27 — Load, quotas, and cost

**Goal:** the free tier survives a launch spike.

**Tasks**
1. Simulate 50–100 analyses with a script.
2. Measure memory and latency per analyzer.
3. Confirm VirusTotal/GSB/urlscan quotas and caching.
4. Add a “degraded mode” when a key hits its quota.
5. Document the expected free-tier limits.
6. Add a cost/upgrade note (what would break first).

**Files:** `scripts/load_test.py`, `documentation/06-API-SETUP.md`.

**Verify:** 50 analyses do not crash; quota errors show “intel unavailable” instead of a stack trace.

**Commit:** `perf: add load test and quota degradation`

**Stretch:** add a tiny cache for repeated public URL checks.

---

### Day 28 — Documentation, screenshots, demo

**Goal:** a stranger can understand and run the project in 5 minutes.

**Tasks**
1. Update the README with the public URL, screenshots, and a 3-step quick start.
2. Record a 2–3 minute demo video/GIF.
3. Add an architecture diagram.
4. Add a “how the score works” section.
5. Add a “limitations” section.
6. Add a “contributing” section.
7. Proofread all docs.

**Files:** `README.md`, `documentation/`, `screenshots/`.

**Verify:** a friend can clone, install, and run without asking you a question.

**Commit:** `docs: add screenshots, demo, and architecture overview`

**Stretch:** publish a short blog post explaining the design decisions.

---

### Day 29 — Beta and fixes

**Goal:** real users find the confusing parts before the public launch.

**Tasks**
1. Invite 10 people (classmates, friends, a small business owner).
2. Ask them to try all five analyzers.
3. Collect: confusing labels, false positives, false negatives, mobile issues.
4. Fix the top 3 issues.
5. Add the issues to a `CHANGELOG.md`.
6. Re-run tests and redeploy.

**Files:** `CHANGELOG.md`, `app.py`, `tests/`.

**Verify:** 10 people completed at least one analysis; top 3 issues fixed; no critical bug remains.

**Commit:** `fix: address beta feedback and improve clarity`

**Stretch:** add a short in-app feedback form (no personal data).

---

### Day 30 — Public launch and retrospective

**Goal:** launch, monitor, and plan the next month.

**Tasks**
1. Publish the final README and public URL.
2. Post on LinkedIn/X/GitHub with a defensive-use statement.
3. Monitor errors, latency, and API quotas for 24 hours.
4. Add a “known issues” section.
5. Write a retrospective: what worked, what was noisy, what to build next.
6. Tag `v1.0.0` and create a GitHub release.
7. Plan Month 2: PDF reports, `.msg`, OCR, ML evaluation, custom domain.

**Files:** `CHANGELOG.md`, `README.md`, GitHub release.

**Verify:** public app is live; release exists; monitoring is in place; next-month plan is written.

**Commit:** `release: PhishGuard v1.0.0 public launch`

**Stretch:** submit the project to a student security showcase or CTF/community demo night.

---

## Daily checklist (print this)

- [ ] Pull latest `main`.
- [ ] Run `PYTHONPATH=src pytest -q`.
- [ ] Build one small increment.
- [ ] Test one malicious and one benign sample.
- [ ] Update docs/README if behaviour changed.
- [ ] Commit with a clear message.
- [ ] Push and confirm CI.
- [ ] Deploy if the change is user-visible.
- [ ] Write 3 lines in your project journal.

---

## Weekly review template

```markdown
## Week N review

**Shipped:**
- ...

**What worked:**
- ...

**What was noisy / broken:**
- ...

**False positives observed:**
- ...

**False negatives observed:**
- ...

**Next week’s top 3:**
1. ...
2. ...
3. ...
```

---

## What “done” means at Day 30

- A public app with five working analyzers.
- A public GitHub repo with a professional README, screenshots, and demo.
- A transparent scoring system and evidence for every verdict.
- Privacy, terms, disclaimer, and security contact.
- Tests and CI.
- Upload/rate limits.
- A launch post and a retrospective.
- A clear Month 2 roadmap.

That is a portfolio project, not just a tutorial.
