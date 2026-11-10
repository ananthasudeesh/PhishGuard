# PhishGuard — API and Threat-Intelligence Setup

> All keys are optional. PhishGuard performs local analysis without them. Intelligence is opt-in per analysis, and only URLs/domains or SHA-256 hashes are sent.

---

## 1. What each service adds

| Service | Adds | Key required | Data sent |
| --- | --- | --- | --- |
| **VirusTotal** | Multi-engine URL/file reputation | Yes | URL or SHA-256 |
| **Google Safe Browsing** | Known malware/social-engineering match | Yes | URL |
| **urlscan.io** | Public scan history for a domain | No (key improves quota) | Domain |
| **RDAP** | Domain registration age | No | Domain |
| **DNS** | A/AAAA/MX/NS/TXT records | No | Hostname |

Optional later:

- **PhishTank** — verified phishing URL feed (registration/API terms apply).
- **OpenPhish** — community feed; check license/terms.
- **URLhaus** — malware URL feed; good for a local blocklist.
- **AbuseIPDB** — IP reputation; less useful for URL-only analysis.
- **MalwareBazaar** — malware sample/hash metadata; check terms.

---

## 2. VirusTotal

### Get a key

1. Create a VirusTotal account.
2. Open **API Key** in your profile.
3. Copy the key.

### Configure

Local `.env`:

```bash
VIRUSTOTAL_API_KEY=your-key
```

Streamlit secrets:

```toml
VIRUSTOTAL_API_KEY = "your-key"
```

### What PhishGuard calls

- URL: `GET https://www.virustotal.com/api/v3/urls/{url_id}`
  - `url_id` is the URL-safe base64 of the URL without padding.
- File: `GET https://www.virustotal.com/api/v3/files/{sha256}`

### Signals

- 3+ malicious engines → critical (85).
- 1–2 malicious → high (65).
- 2+ suspicious → medium (45).
- No detections → info (0), never “safe”.

### Free-tier reality

Free-tier quotas are small (requests per minute and per day). Check the current limits in your VirusTotal account. PhishGuard caches results for 15 minutes and only calls VT when the user opts in.

### Privacy note

VirusTotal may retain submitted URLs/hashes according to its terms. Do not send confidential URLs without consent. Never send raw email bodies or file bytes.

---

## 3. Google Safe Browsing

### Get a key

1. Open the Google Cloud Console.
2. Create/select a project.
3. Enable **Safe Browsing API**.
4. Create an API key.
5. Restrict the key to the Safe Browsing API and your deployment if possible.

### Configure

```bash
GOOGLE_SAFE_BROWSING_API_KEY=your-key
```

### What PhishGuard calls

`POST https://safebrowsing.googleapis.com/v4/threatMatches:find`

Threat types:

- `MALWARE`
- `SOCIAL_ENGINEERING`
- `UNWANTED_SOFTWARE`
- `POTENTIALLY_HARMFUL_APPLICATION`

A match → critical signal (85).

### Notes

- The API returns matches, not a “safe” verdict. No match is not proof of safety.
- Check current quotas and terms.
- Restrict the key; do not expose it client-side.

---

## 4. urlscan.io

### Key

urlscan.io allows limited anonymous search. A free API key improves quota and access.

1. Create an account.
2. Find the API key in your account settings.
3. Add `URLSCAN_API_KEY`.

### What PhishGuard calls

`GET https://urlscan.io/api/v1/search/?q=domain:<domain>&size=20`

It counts recent results with malicious verdicts or a high overall score.

### Signals

- 1+ malicious scan → high (60).
- 2+ suspicious scans → medium (35).
- No results → info (0).

### Notes

- Search results are public; do not submit private URLs.
- Rate limits apply; cache results.
- A domain with no scans is unknown, not safe.

---

## 5. RDAP (domain age)

No key. PhishGuard calls:

```text
https://rdap.org/domain/<domain>
```

It reads the registration event and computes age in days.

Signals:

- < 30 days → high (30).
- < 90 days → medium (15).
- Older → no signal.

RDAP availability varies by registry. Timeouts are treated as “unknown”, not “old”.

---

## 6. DNS and TLS

No key.

- DNS: A/AAAA/MX/NS/TXT with a 3-second lifetime.
- TLS: connect to a validated public IP on port 443 with the original hostname for SNI.
- No HTTP request, no redirects, no page rendering.

---

## 7. Configuration reference

| Variable | Required | Default | Notes |
| --- | --- | --- | --- |
| `VIRUSTOTAL_API_KEY` | No | empty | URL/file reputation |
| `GOOGLE_SAFE_BROWSING_API_KEY` | No | empty | URL threat match |
| `URLSCAN_API_KEY` | No | empty | higher urlscan quota |
| `PHISHGUARD_MAX_UPLOAD_MB` | No | `10` | app upload limit |
| `PHISHGUARD_RATE_LIMIT` | No | `20` | per session per hour |
| `PHISHGUARD_REPO_URL` | No | repo URL | sidebar links |

---

## 8. Testing your keys

### Local

```bash
export VIRUSTOTAL_API_KEY="..."
export GOOGLE_SAFE_BROWSING_API_KEY="..."
export URLSCAN_API_KEY="..."
streamlit run app.py
```

Run a URL analysis with **Use opt-in threat intelligence** checked. Open **Technical details** and confirm the `virustotal`, `safe_browsing`, and `urlscan` metadata blocks.

### Without keys

The app must still work. Confirm:

- no crash,
- `metadata["intel_errors"]` explains missing keys,
- local signals still produce a verdict.

### Quota errors

If you see HTTP 429:

- wait,
- reduce analyses,
- keep the 15-minute cache,
- consider a paid tier or a queue,
- show “intel unavailable” in the UI.

---

## 9. Security rules for keys

- Never commit a key.
- Never put a key in client-side JavaScript.
- Never log a key.
- Rotate immediately if exposed.
- Use separate keys for development and production.
- Restrict Google keys by API and referrer/IP where possible.
- Monitor provider usage for unexpected spikes.

---

## 10. Future intelligence sources

If you add a feed:

1. Check the license and terms.
2. Prefer a local cache/blocklist over a live API for high-volume checks.
3. Normalize to the `IntelResult` shape.
4. Add a signal with a clear source and weight.
5. Add a test with a mocked response.
6. Document the privacy impact.

Do not add a source that requires uploading raw user files without explicit consent.
