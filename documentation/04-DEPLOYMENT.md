# PhishGuard — Deployment Guide

> **Target:** a free, public app on Streamlit Community Cloud, backed by a public GitHub repository.

---

## 1. Prerequisites

- A GitHub account.
- A Streamlit Community Cloud account (sign in with GitHub).
- Python 3.11 or 3.12 locally (3.13/3.14 may work, but 3.11/3.12 is the safest for the dependency set).
- Git.
- Optional API keys: VirusTotal, Google Safe Browsing, urlscan.io.

---

## 2. Local run

```bash
cd ~/PhishGuard
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
streamlit run app.py
```

Open `http://localhost:8501`.

If port 8501 is busy:

```bash
streamlit run app.py --server.port 8502
```

---

## 3. Repository setup

### 3.1 Check the current state

```bash
cd ~/PhishGuard
git status
git remote -v
git branch --show-current
git log --oneline -3
```

### 3.2 If there is no commit yet

```bash
git add .
git commit -m "chore: initial PhishGuard scaffold"
git branch -M main
```

### 3.3 Create the public GitHub repository

Option A — GitHub CLI:

```bash
gh repo create PhishGuard --public --source=. --remote=origin --push
```

Option B — GitHub website:

1. Create a new public repository named `PhishGuard`.
2. Do **not** initialize with a README (you already have one).
3. Add the remote and push:

```bash
git remote add origin https://github.com/<your-username>/PhishGuard.git
git push -u origin main
```

### 3.4 Verify

```bash
git remote -v
git log --oneline -1
```

Open the repository in a private browser window to confirm it is public.

---

## 4. Streamlit Community Cloud deployment

### 4.1 Create the app

1. Go to [https://share.streamlit.io](https://share.streamlit.io).
2. Sign in with GitHub.
3. Click **New app**.
4. Choose:
   - **Repository:** `<your-username>/PhishGuard`
   - **Branch:** `main`
   - **Main file path:** `app.py`
5. (Optional) Choose a custom subdomain.
6. Click **Deploy**.

### 4.2 Python version

In **Advanced settings**, select Python **3.11** or **3.12**. If a dependency fails, check the build logs and pin versions.

### 4.3 Secrets

In **App settings → Secrets**, paste:

```toml
VIRUSTOTAL_API_KEY = "your-virustotal-key"
GOOGLE_SAFE_BROWSING_API_KEY = "your-google-key"
URLSCAN_API_KEY = "your-urlscan-key"
PHISHGUARD_MAX_UPLOAD_MB = "10"
PHISHGUARD_RATE_LIMIT = "20"
PHISHGUARD_REPO_URL = "https://github.com/<your-username>/PhishGuard"
```

Notes:

- Secrets are server-side; they are not sent to the browser.
- If you leave a key empty, the app still works with local checks + public urlscan/RDAP.
- After changing secrets, the app may restart automatically. If not, use **Reboot app**.

### 4.4 Verify the deployment

```bash
curl -I https://<your-app>.streamlit.app
```

Open it on desktop and mobile. Test:

- a benign URL,
- a lookalike URL,
- an `.eml` sample,
- a QR image,
- a fake `invoice.pdf.exe`,
- a scam social message.

---

## 5. Custom domain (optional)

Streamlit Community Cloud supports custom domains on some plans. The general process:

1. Add your domain in the Streamlit app settings.
2. Create the required `CNAME` record at your DNS provider.
3. Wait for DNS propagation and TLS provisioning.
4. Update `PHISHGUARD_REPO_URL` and README links.

If custom domains are unavailable on your plan, use the `*.streamlit.app` URL and a short link from your portfolio.

---

## 6. GitHub Actions CI

Create `.github/workflows/tests.yml`:

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
      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -r requirements.txt
      - name: Run tests
        env:
          PYTHONPATH: src
        run: pytest -q
```

Optional additions:

```yaml
      - name: Lint
        run: |
          pip install ruff
          ruff check .
```

Do not put API keys in the workflow. Tests must run without them.

---

## 7. Updating the app

```bash
git add .
git commit -m "feat: ..."
git push origin main
```

Streamlit Cloud redeploys automatically from `main`. Watch the build logs for dependency or import errors.

### Rollback

If a deploy breaks:

1. Find the last working commit:
   ```bash
   git log --oneline -10
   ```
2. Revert:
   ```bash
   git revert <bad-commit>
   git push origin main
   ```
3. Or redeploy the previous commit from the Streamlit dashboard if available.
4. Confirm the public URL and a smoke test.

---

## 8. Common deployment problems

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| `ModuleNotFoundError: phishguard` | `src` not on path | `app.py` inserts `src` into `sys.path`; verify the import block |
| `ImportError: libGL.so.1` | `opencv-python` instead of headless | Use `opencv-python-headless` |
| `ModuleNotFoundError: magic` | `python-magic` needs libmagic | The MVP does not require it; remove it or install `libmagic1` |
| Build times out | Heavy dependencies | Keep OpenCV headless; avoid unnecessary packages |
| App sleeps | Free-tier inactivity | Open it once before a demo; upgrade if needed |
| Secrets not found | Wrong TOML syntax or app not rebooted | Check quotes, reboot the app |
| `ValueError: maxUploadSize` | Invalid config | Use an integer in `.streamlit/config.toml` |
| Rate limit too strict | Env var typo | Check `PHISHGUARD_RATE_LIMIT` |
| API quota errors | Free-tier limit | Cache, opt-in, degrade gracefully |
| App is slow | RDAP/DNS timeouts | Keep 3–6s timeouts; skip on failure |

---

## 9. Free-tier limits and expectations

- Streamlit Community Cloud apps sleep after inactivity.
- Memory/CPU are shared; avoid heavy processing.
- No persistent disk; do not write reports to disk.
- No built-in WAF; application-level limits are essential.
- Logs are limited; add external uptime monitoring if needed.
- API free tiers are small; caching and opt-in are required.

---

## 10. Production checklist

- [ ] `main` is the deploy branch.
- [ ] CI is green.
- [ ] Secrets are set in Streamlit, not in Git.
- [ ] `.env` is ignored.
- [ ] Upload limit is 10 MB.
- [ ] Rate limit is 20/hour/session.
- [ ] App is reachable over HTTPS.
- [ ] Privacy, ToS, disclaimer, security contact are linked.
- [ ] Tested on mobile.
- [ ] Rollback commit identified.
- [ ] API quota dashboard checked.
- [ ] Uptime monitor configured (optional).
- [ ] README has the public URL and screenshots.

---

## 11. Day 1 verification

If your local repo has no commits/remote, run:

```bash
cd ~/PhishGuard
git init
git add .
git commit -m "chore: initial PhishGuard scaffold"
git branch -M main
gh repo create PhishGuard --public --source=. --remote=origin --push
```

Then deploy `app.py` on Streamlit Cloud and add the URL to the README.

Detailed recovery: [`07-DAY-01-VERIFICATION.md`](07-DAY-01-VERIFICATION.md).
