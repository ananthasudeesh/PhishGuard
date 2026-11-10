# PhishGuard — Security, Privacy, and Legal Guide

> A public phishing analyzer accepts hostile input from strangers. Treat every URL, email, QR image, and file as malicious until proven otherwise.

---

## 1. Security goals

1. A malicious URL cannot make the server connect to internal services (SSRF).
2. A malicious file cannot execute code or exhaust memory/disk (RCE/DoS).
3. User content cannot inject HTML/JavaScript into the UI (XSS).
4. API keys and secrets cannot leak to the browser or Git history.
5. Abuse cannot burn through free-tier quotas or turn the app into a scanning service.
6. Uploaded personal data is not retained beyond the request.
7. The app fails safely: errors are contained, not exposed as tracebacks.

---

## 2. Threat model (STRIDE)

| Threat | Example | Control |
| --- | --- | --- |
| **Spoofing** | Attacker pretends to be a legitimate user | No accounts in MVP; per-session limits; optional Turnstile |
| **Tampering** | Malformed `.eml`/ZIP/PDF crashes parser | Size limits, try/except, no extraction, parser timeouts |
| **Repudiation** | Abuse cannot be traced | Redacted request counts, not content; no need to identify users |
| **Information disclosure** | Victim email/file leaked via logs or cache | No storage, no body logging, no shared cache, TLS |
| **Denial of service** | Zip bomb, huge upload, API quota exhaustion | 10 MB upload cap, archive caps, rate limit, intel cache |
| **Elevation of privilege** | SSRF to cloud metadata / internal admin | Resolve and reject private/reserved IPs; no page fetch |
| **XSS** | Filename/URL rendered as HTML | `unsafe_allow_html=False`, data tables, no raw HTML |
| **Secret leakage** | Key in repo or browser | Streamlit secrets, `.gitignore`, server-side calls only |
| **Supply chain** | Malicious dependency | Pin ranges, `pip-audit`, review updates |

### Out of scope for the MVP

- Full sandbox detonation.
- Multi-tenant isolation.
- Compliance certification (SOC 2, ISO 27001).
- Protection against a determined nation-state attacker.
- Guaranteeing that a URL/file is safe.

---

## 3. SSRF: the most important URL control

### The risk

If the app fetches a user-supplied URL with a normal HTTP client, an attacker can request:

```text
http://169.254.169.254/latest/meta-data/        # cloud metadata
http://127.0.0.1:8501/                          # local services
http://10.0.0.5/admin                           # internal network
http://[::1]/                                   # loopback
```

This is server-side request forgery. On a cloud host, it can expose credentials.

### The MVP control

PhishGuard **does not fetch the page**. It only:

1. resolves DNS,
2. rejects the host if any answer is private/reserved,
3. connects to a validated public IP for a TLS handshake, with the original hostname for SNI.

```python
ips = resolve_public_ips(host)          # rejects private/reserved
with socket.create_connection((ips[0], 443), timeout=4) as sock:
    with context.wrap_socket(sock, server_hostname=host) as tls:
        ...
```

### Additional rules

- Do not follow HTTP redirects. (There is no HTTP request.)
- Reject IPv4/IPv6 literals that are not global.
- Reject mixed public/private DNS answers.
- Keep DNS/TLS timeouts short (3–4 seconds).
- Do not add a “fetch page” feature without a dedicated egress proxy and allowlist.

### If you later add page fetching

Use a separate sandboxed service with:

- no access to the cloud metadata endpoint,
- an egress allowlist/proxy,
- DNS pinning and re-validation on every redirect,
- a headless browser in a disposable container,
- no credentials,
- strict time/memory limits.

Do not add it to the Streamlit process.

---

## 4. File upload safety

### Controls in the MVP

- 10 MB public upload limit (Streamlit + app check).
- 25 MB analyzer limit.
- No execution, no extraction to disk.
- ZIP inspection reads metadata only; no `extractall()`.
- 2,000-entry archive cap.
- 200 MB uncompressed ceiling for the bomb check.
- Path-traversal detection.
- Password-protected archive detection.
- Malformed input returns an error result.

### Threats

| Threat | Control |
| --- | --- |
| Executable attachment | Magic-byte + extension detection; never run |
| Macro document | OLE/OOXML `vbaProject.bin` detection |
| PDF JavaScript/launch | Raw action scanning |
| Zip bomb | Entry count, uncompressed size, compression ratio |
| Path traversal | Reject `../` and absolute paths in entries |
| Encrypted archive | Flag and refuse to analyze contents |
| HTML smuggling | Script + base64/atob heuristic |
| Polyglot file | Magic + extension mismatch + multiple signatures |

### What not to do

- Do not call `subprocess` on uploaded files.
- Do not use `pickle`, `eval`, or `exec` on user content.
- Do not extract archives to a shared directory.
- Do not pass user content to a shell.
- Do not rely on the filename extension alone.

---

## 5. XSS and output safety

- Streamlit escapes Markdown/HTML by default. Keep `unsafe_allow_html=False` for user content.
- The only `unsafe_allow_html=True` use is for static CSS and generated verdict badges (no user data).
- Render signals in `st.dataframe`, not raw HTML.
- Do not render uploaded email HTML.
- Do not embed the user’s URL in an `<a href>` without validation.
- Sanitize/truncate evidence before display.
- If you add a shareable report page, escape all fields and use a strict CSP.

---

## 6. Secrets management

### Rules

- Never commit `.env`, API keys, tokens, or Streamlit secrets.
- Keep `.env.example` with empty values.
- Use Streamlit secrets in production.
- Use environment variables locally.
- Rotate a key immediately if it was ever committed.
- Do not log request headers or keys.
- Do not expose keys in error messages.
- Use separate keys for dev and prod if possible.

### Check for leaks

```bash
git log -p | grep -iE 'api[_-]?key|secret|token|password' | head
git grep -iE 'api[_-]?key|secret|token' -- . ':!*.md'
```

If a key leaked:

1. Revoke/rotate it in the provider dashboard.
2. Remove it from the current files.
3. If it is in Git history, rewrite history (or, for a public repo, assume it is compromised and rotate).
4. Document the incident.

---

## 7. Abuse and quota control

### Application-level

- 20 analyses per session per hour (configurable).
- 10 MB upload limit.
- Intel opt-in.
- 15-minute intel cache.
- Friendly “limit reached” message.
- Optional Cloudflare Turnstile.

### Why session limits are not enough

A user can clear cookies or open a new session. For a serious public launch, add:

- per-IP limits at a gateway/WAF,
- Turnstile or proof-of-work,
- a queue for expensive analyses,
- provider-side quota alerts.

### API quota plan

| Service | Free-tier concern | Mitigation |
| --- | --- | --- |
| VirusTotal | Requests/minute and daily quota | Cache, opt-in, degrade gracefully |
| Google Safe Browsing | Quota | Cache, opt-in |
| urlscan.io | Anonymous rate limit | Cache, optional key |
| RDAP | Per-registry limits | Cache, timeout, skip on failure |

When a quota is hit, show “intel unavailable” and keep local signals. Never show a stack trace.

---

## 8. Privacy principles

### Data minimisation

- Process only what the user submits.
- Do not require an account.
- Do not ask for a name, email, or phone number.
- Do not store uploads or reports.

### Purpose limitation

- Data is used only to produce the requested analysis.
- No advertising, profiling, or model training on user uploads.
- No sale of data.

### Storage limitation

- MVP: in-memory only; discarded when the request ends.
- If you add history later, make it opt-in, encrypted, and deletable.

### Transparency

- Tell users what is processed.
- Tell them which third parties receive URLs/hashes.
- Tell them the limits of the result.
- Link the privacy policy and disclaimer on every page.

### Third parties

| Service | Data sent | When |
| --- | --- | --- |
| VirusTotal | URL or SHA-256 hash | Only if user opts in |
| Google Safe Browsing | URL | Only if user opts in |
| urlscan.io | Domain | Only if user opts in |
| RDAP registry | Domain | For domain-age lookup (public registration data) |
| DNS resolver | Hostname | For DNS/TLS checks |

Do not send raw email bodies, attachment bytes, or filenames to third parties.

---

## 9. Privacy policy outline

A public app needs a real policy, not a one-line “we respect privacy”. Include:

1. **Who we are** and contact details.
2. **What we collect**:
   - input you submit (URL, email, file, QR image, text),
   - technical data (IP address, browser, timestamps) if the host logs it,
   - no account data.
3. **Why** (to perform the analysis, security, abuse prevention).
4. **Legal basis** (consent / legitimate interest, depending on jurisdiction).
5. **Retention**: in-memory only; logs redacted; no upload storage.
6. **Third parties** and links to their policies.
7. **International transfers** if applicable.
8. **Your rights** (access, deletion, objection, complaint).
9. **Children** (not directed at children).
10. **Changes** and effective date.
11. **Security** measures.
12. **Contact** for privacy requests.

Template: [`08-LAUNCH-TEMPLATES.md`](08-LAUNCH-TEMPLATES.md).

---

## 10. Terms of use outline

- Acceptable use: defensive analysis only.
- Prohibited use: creating phishing, credential harvesting, unauthorized scanning, malware distribution, harassment.
- No warranty: results are indicators, not proof.
- Limitation of liability.
- Intellectual property and open-source license.
- Termination/abuse.
- Governing law.
- Changes.
- Contact.

---

## 11. Legal considerations by region

| Region | Consider |
| --- | --- |
| India | Digital Personal Data Protection Act, 2023; IT Act; CERT-In directions; reasonable security practices |
| EU/UK | GDPR/UK GDPR; lawful basis; data subject rights; international transfers; ePrivacy |
| US | State privacy laws (CCPA/CPRA etc.); CFAA concerns; CAN-SPAM not relevant to defense |
| Global | Computer-misuse laws; do not access systems without authorization; do not store victim data |

This is not legal advice. For a public app with meaningful traffic, get a review.

---

## 12. Logging and monitoring

### Log

- timestamp,
- analyzer type,
- success/failure,
- latency,
- coarse error category,
- rate-limit events.

### Do not log

- email bodies,
- filenames,
- URLs (they may contain tokens/PII),
- IP addresses longer than needed,
- API keys,
- full exception traces in production.

### Alert on

- error rate > 5%,
- p95 latency > 10s,
- API quota errors,
- a spike in analyses,
- repeated oversized uploads,
- deployment failure.

---

## 13. Incident response

### Leaked API key

1. Revoke/rotate immediately.
2. Remove from code and secrets.
3. Check provider usage for abuse.
4. If the repo is public, assume the key was scraped.
5. Document and add a prevention step.

### Abuse / scanning

1. Enable Turnstile or per-IP limits.
2. Temporarily disable intel.
3. Review rate-limit logs.
4. Block abusive sessions/IPs at the edge if possible.
5. Communicate if service is degraded.

### Data exposure

1. Stop the exposure.
2. Identify what was exposed (ideally nothing, because you store nothing).
3. Notify affected users if required by law.
4. Document root cause and fix.

### Compromised dependency

1. Pin/rollback.
2. Run tests and `pip-audit`.
3. Redeploy.
4. Review for data access.

---

## 14. Security checklist before public launch

- [ ] No secrets in Git history.
- [ ] `.env` ignored; `.env.example` empty.
- [ ] Upload limit enforced server-side and in app.
- [ ] Rate limit enforced.
- [ ] SSRF guard tested with private IPs.
- [ ] No page fetch.
- [ ] No file execution/extraction.
- [ ] Zip-bomb/path-traversal checks.
- [ ] XSS-safe rendering.
- [ ] Error messages do not leak stack traces.
- [ ] Privacy/ToS/disclaimer/security contact published.
- [ ] Dependency audit.
- [ ] Backups/rollback plan.
- [ ] Monitoring and quota alerts.
- [ ] Incident-response contacts.

---

## 15. Responsible disclosure

Add a `SECURITY.md`:

```markdown
# Security policy

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
