<div align="center">

# 🔐 Secrets Detector

### Find hardcoded API keys, passwords & credentials in your codebase — before attackers do

[![Python](https://img.shields.io/badge/Python-3.9+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Stars](https://img.shields.io/github/stars/khaledxbenali92/secrets-detector?style=for-the-badge&color=yellow)](https://github.com/khaledxbenali92/secrets-detector/stargazers)
[![CI](https://img.shields.io/github/actions/workflow/status/khaledxbenali92/secrets-detector/ci.yml?style=for-the-badge&label=CI)](https://github.com/khaledxbenali92/secrets-detector/actions)
[![Issues](https://img.shields.io/github/issues/khaledxbenali92/secrets-detector?style=for-the-badge)](https://github.com/khaledxbenali92/secrets-detector/issues)

[Features](#-features) • [Demo](#-demo) • [Installation](#-installation) • [Usage](#-usage) • [Rules](#-detection-rules) • [CI/CD](#-cicd-integration) • [Contributing](#-contributing)

</div>

---

## 🚨 The Problem

Every week, thousands of developers accidentally push API keys, passwords, and credentials to public repositories.

The consequences:
- 💸 **AWS keys** exposed = bills of thousands of dollars in minutes
- 🔓 **Database credentials** leaked = full data breach
- 💳 **Stripe keys** exposed = fraudulent transactions
- 🤖 **OpenAI keys** stolen = huge API costs

**Secrets Detector** scans your entire codebase and git history in seconds, finding these vulnerabilities before attackers do.

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔍 **80+ Detection Rules** | AWS, GitHub, Stripe, OpenAI, Slack, Firebase, and more |
| 📊 **4 Severity Levels** | Critical, High, Medium, Low |
| 📄 **3 Output Formats** | Console (colored), JSON, HTML report |
| 📜 **Git History Scan** | Scan past commits for leaked secrets |
| 🚫 **Smart Filtering** | Ignores placeholders and test values |
| 🔧 **Remediation Tips** | Each finding includes exact fix instructions |
| ⚡ **Zero Dependencies** | Runs with standard Python — no heavy installs |
| 🔄 **CI/CD Ready** | GitHub Actions workflow included |
| 🎨 **HTML Reports** | Beautiful dark-theme security reports |

---

## 🎬 Demo

```bash
$ python main.py scan --path ./my-project

╔══════════════════════════════════════════════════════════╗
║           🔐 Secrets Detector v1.0                       ║
╚══════════════════════════════════════════════════════════╝

🔍 Scanning: ./my-project

🔴 CRITICAL (2 found)
────────────────────────────────────────────────────────────
Rule:     AWS Access Key ID
File:     src/config.py:14
Match:    AKIA**************23
Fix:      Revoke immediately at AWS Console → IAM → Security Credentials

Rule:     OpenAI API Key
File:     .env.backup:3
Match:    sk-proj-********************xyz
Fix:      Revoke at platform.openai.com/api-keys

🟠 HIGH (1 found)
────────────────────────────────────────────────────────────
Rule:     Stripe Secret Key
File:     src/payment.py:8
Match:    sk_live_**************abc
Fix:      Rotate immediately at dashboard.stripe.com/apikeys

──────────────────────────────────────────────────────────
📊 SCAN SUMMARY
Files scanned:  47
Total findings: 3
  🔴 Critical: 2
  🟠 High:     1
⚠️  Secrets found! Fix before committing.
```

---

## 🛡️ Detection Rules

Secrets Detector includes **80+ rules** across these categories:

| Category | Examples |
|----------|---------|
| ☁️ **Cloud** | AWS Access Key, AWS Secret, GCP Service Account, Firebase, DigitalOcean |
| 💳 **Payment** | Stripe Live/Test, PayPal, Square |
| 🤖 **AI** | OpenAI API Key, Anthropic, Cohere, Hugging Face |
| 💬 **Communication** | Slack Token, Slack Webhook, Telegram Bot, Twilio |
| 📧 **Email** | SendGrid, Mailgun, Mailchimp, Postmark |
| 🔐 **Cryptography** | RSA Private Key, EC Private Key, PGP Key, SSH Key |
| 🗄️ **Database** | MongoDB URI, PostgreSQL, MySQL, Redis with credentials |
| 🔑 **Authentication** | JWT Secret, OAuth Tokens, Basic Auth |
| 📦 **Version Control** | GitHub Tokens (all types), GitLab, Bitbucket |
| 🌐 **Generic** | Generic API keys, passwords, secrets patterns |

```bash
# List all rules
python main.py rules

# Filter by category
python main.py rules --category Cloud
```

---

## 🛠️ Installation

### Prerequisites
- Python 3.9+

### Option 1 — Clone & Run (Recommended)

```bash
git clone https://github.com/khaledxbenali92/secrets-detector.git
cd secrets-detector
pip install -r requirements.txt
```

### Option 2 — Quick install

```bash
git clone https://github.com/khaledxbenali92/secrets-detector.git
cd secrets-detector
python main.py --help
```

---

## 📖 Usage

### Scan a directory

```bash
# Basic scan
python main.py scan --path ./my-project

# Only show high and critical
python main.py scan --path . --severity high

# Exclude directories
python main.py scan --path . --exclude tests/ --exclude node_modules/

# Save as JSON
python main.py scan --path . --format json --output results.json

# Generate HTML report
python main.py scan --path . --format html --output report.html
```

### Scan a single file

```bash
python main.py scan --path ./src/config.py
```

### Scan git history

```bash
# Scan last 20 commits (default)
python main.py git

# Scan last 100 commits
python main.py git --commits 100

# Scan specific branch
python main.py git --commits 50 --branch develop
```

### Full security audit

```bash
# Generates a detailed HTML report
python main.py audit --path ./my-project --output audit.html
```

### List all detection rules

```bash
python main.py rules
python main.py rules --category Payment
```

---

## 🔄 CI/CD Integration

### GitHub Actions

The repository includes a ready-to-use GitHub Actions workflow.

Add to your project's `.github/workflows/secrets-scan.yml`:

```yaml
name: 🔐 Secrets Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    - uses: actions/setup-python@v4
      with:
        python-version: "3.11"
    - run: |
        git clone https://github.com/khaledxbenali92/secrets-detector.git detector
        cd detector && pip install -r requirements.txt
        python main.py scan --path ../ --severity high
```

This will **block pull requests** if high/critical secrets are found. ✅

### Pre-commit Hook

Add to `.git/hooks/pre-commit`:

```bash
#!/bin/bash
python /path/to/secrets-detector/main.py scan --path . --severity high
if [ $? -ne 0 ]; then
    echo "🔐 Secrets detected! Commit blocked."
    exit 1
fi
```

```bash
chmod +x .git/hooks/pre-commit
```

---

## 📁 Project Structure

```
secrets-detector/
├── main.py                      # CLI entry point
├── src/
│   ├── __init__.py
│   ├── scanner.py               # Core scanning engine
│   ├── rules.py                 # 80+ detection rules
│   ├── reporters/
│   │   ├── console.py           # Colored terminal output
│   │   ├── json_reporter.py     # JSON export
│   │   └── html_reporter.py     # Beautiful HTML report
│   └── utils/
│       └── display.py           # UI utilities
├── tests/
│   └── test_scanner.py          # Full test suite
├── .github/
│   └── workflows/
│       └── ci.yml               # GitHub Actions CI
├── requirements.txt
├── .gitignore
└── README.md
```

---

## 🧪 Running Tests

```bash
# Install pytest
pip install pytest pytest-cov

# Run tests
pytest tests/ -v

# With coverage report
pytest tests/ --cov=src --cov-report=term-missing
```

---

## 🗺️ Roadmap

- [x] 80+ detection rules
- [x] Console, JSON, HTML reporters
- [x] Git history scanning
- [x] Smart placeholder filtering
- [x] GitHub Actions integration
- [x] Pre-commit hook support
- [ ] VS Code Extension
- [ ] PyPI package (`pip install secrets-detector`)
- [ ] Custom rules via YAML config
- [ ] Slack/Discord notifications
- [ ] Baseline file (ignore known false positives)
- [ ] Web dashboard

---

## 🤝 Contributing

Contributions are very welcome! Here's how:

### Add a new detection rule

Edit `src/rules.py` and add your rule:

```python
{
    "id": "MY_SERVICE_KEY",
    "name": "My Service API Key",
    "category": "My Category",
    "severity": "high",  # critical / high / medium / low
    "pattern": r"myservice_[a-zA-Z0-9]{32}",
    "description": "My Service API Key — what it can access",
    "remediation": "How to revoke/rotate this secret",
},
```

Then add a test in `tests/test_scanner.py`.

### Contribution Steps

```bash
# Fork & clone
git clone https://github.com/YOUR-USERNAME/secrets-detector.git
cd secrets-detector

# Create branch
git checkout -b feat/add-my-service-rule

# Make changes + add tests
pytest tests/ -v  # must pass

# Commit
git commit -m "feat: add My Service API key detection"
git push origin feat/add-my-service-rule

# Open Pull Request
```

### What We Need
- 🔑 New service API key patterns
- 🌍 Translations of the README
- 🧪 More test cases
- 📖 Documentation improvements
- 🐛 Bug reports

---

## ⚠️ Disclaimer

This tool is for **defensive security** purposes only. Use it on codebases you own or have explicit permission to scan. The authors are not responsible for misuse.

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

## 👨‍💻 Author

**Khaled Ben Ali** — Cybersecurity & Full-Stack Founder

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-0077B5?style=flat&logo=linkedin)](https://linkedin.com/in/benalikhaled)
[![Twitter](https://img.shields.io/badge/Twitter-Follow-1DA1F2?style=flat&logo=twitter)](https://twitter.com/khaledbali92)
[![GitHub](https://img.shields.io/badge/GitHub-Follow-333?style=flat&logo=github)](https://github.com/khaledxbenali92)

---

<div align="center">

⭐ **If this tool helped secure your codebase, please star it!** ⭐

*Every star helps more developers find this tool and keep their secrets safe.*

</div>
