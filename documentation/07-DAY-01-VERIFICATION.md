# PhishGuard — Day 1 Verification and Recovery

> **Purpose:** make sure Day 1 is genuinely complete: environment ready, public GitHub repo live, public web app reachable.  
> **Current local state:** this repository has source files and tests, but the local Git history/remote may still be missing. Use the checks below.

---

## 1. Environment checks

```bash
whoami
cat /etc/os-release
df -h /
free -h
python3 --version
python3 -m pip --version
git --version
code --version
python3 -m venv --help >/dev/null && echo "venv OK"
```

Expected:

- Kali/Debian (or your distro).
- Python 3.11+ (3.11/3.12 recommended for deployment).
- Git installed.
- VS Code installed (optional).
- venv available.
- At least a few GB free.

---

## 2. Project checks

```bash
cd ~/PhishGuard
ls -la
find . -maxdepth 2 -type f -not -path './.git/*' | sort
```

Expected files:

```text
app.py
requirements.txt
README.md
LICENSE
.gitignore
.env.example
.streamlit/config.toml
src/phishguard/...
tests/...
documentation/...
```

If `src/` is empty or `requirements.txt` is empty, the reference implementation was not copied. Restore it from this workspace or continue with the guide.

---

## 3. Git checks

```bash
git status
git remote -v
git branch --show-current
git log --oneline -5
```

Healthy state:

- branch `main`,
- remote `origin` pointing to GitHub,
- at least one commit,
- clean working tree (or only intentional changes).

If you see:

```text
fatal: your current branch 'master' does not have any commits yet
```

then Git is initialized but nothing has been committed. Continue with section 4.

If `git remote -v` is empty, continue with section 5.

---

## 4. First commit

```bash
cd ~/PhishGuard
git add .
git status
git commit -m "chore: initial PhishGuard scaffold and working MVP"
git branch -M main
```

Verify:

```bash
git log --oneline -1
git status
```

---

## 5. Create and connect the public GitHub repository

### Option A — GitHub CLI

```bash
gh auth status
gh repo create PhishGuard --public --source=. --remote=origin --push
```

If `gh` is not installed:

```bash
sudo apt update && sudo apt install -y gh
gh auth login
```

### Option B — GitHub website

1. Go to GitHub → **New repository**.
2. Name: `PhishGuard`.
3. Visibility: **Public**.
4. Do **not** add a README, `.gitignore`, or license (you already have them).
5. Create the repository.
6. Run:

```bash
git remote add origin https://github.com/<your-username>/PhishGuard.git
git push -u origin main
```

Verify:

```bash
git remote -v
git log --oneline -1
```

Open the repository in a private browser window. It must be visible without login.

---

## 6. Public app deployment

1. Go to [https://share.streamlit.io](https://share.streamlit.io).
2. Sign in with GitHub.
3. **New app**.
4. Repository: `<your-username>/PhishGuard`.
5. Branch: `main`.
6. Main file path: `app.py`.
7. Advanced settings → Python 3.11/3.12.
8. Add secrets if you have them (optional).
9. Deploy.

Verify:

```bash
curl -I https://<your-app>.streamlit.app
```

Open it on desktop and mobile. The five tabs should render.

---

## 7. Add the public URL to the README

Replace:

```markdown
> **Public demo:** `https://<your-app>.streamlit.app` (replace after deployment)
```

with your real URL.

Commit:

```bash
git add README.md
git commit -m "docs: add public demo URL"
git push origin main
```

---

## 8. Day 1 acceptance checklist

- [ ] Python, pip, Git, venv verified.
- [ ] Project structure present.
- [ ] `requirements.txt` has real dependencies.
- [ ] `.gitignore` protects `.env`, uploads, reports, caches.
- [ ] `.env.example` exists and contains no real keys.
- [ ] Git repo has a `main` branch and at least one commit.
- [ ] GitHub repo is public.
- [ ] `origin` remote points to the correct repo.
- [ ] Streamlit app deploys successfully.
- [ ] Public URL returns HTTP 200.
- [ ] All five tabs render.
- [ ] README contains the public URL.
- [ ] No secrets in the repository.

---

## 9. Troubleshooting

### `src` is missing or empty

Copy the reference implementation from the workspace:

```bash
ls ~/PhishGuard/src/phishguard
```

If empty, re-create the files from the guide or restore from the provided project.

### `requirements.txt` is empty

Use the project requirements:

```bash
cat > requirements.txt <<'EOF'
streamlit>=1.40,<2
requests>=2.32,<3
dnspython>=2.7,<3
tldextract>=5.1,<6
beautifulsoup4>=4.12,<5
Pillow>=10,<12
opencv-python-headless>=4.10,<6
olefile>=0.47,<1
pytest>=8,<9
EOF
```

### `git push` asks for credentials

Use a personal access token or `gh auth login`. Do not paste a token into a file.

### Streamlit build fails

Check the build log. Common causes:

- wrong entrypoint (`app.py`),
- missing `src` path handling,
- `opencv-python` instead of `opencv-python-headless`,
- Python version too new for a dependency.

### App is public but shows an error

Open **Manage app → Logs**. Fix the first traceback, push, and let it redeploy.

### No API keys

That is fine. The app works with local checks + public urlscan/RDAP. Add keys later.

---

## 10. What Day 1 is *not*

Day 1 is not “the project is finished”. It is the foundation:

- a public repo,
- a public URL,
- a working “hello” app,
- a safe place to commit daily.

Day 2 starts the real build: repository hygiene, CI, data models, and scoring.
