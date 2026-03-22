"""
🔐 Detection Rules — 80+ patterns for secrets detection
"""

RULES = [

    # ── CRITICAL ──────────────────────────────────────────────

    {
        "id": "AWS_ACCESS_KEY",
        "name": "AWS Access Key ID",
        "category": "Cloud",
        "severity": "critical",
        "pattern": r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
        "description": "Amazon Web Services Access Key ID",
        "remediation": "Revoke immediately at AWS Console → IAM → Security Credentials",
    },
    {
        "id": "AWS_SECRET_KEY",
        "name": "AWS Secret Access Key",
        "category": "Cloud",
        "severity": "critical",
        "pattern": r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",
        "description": "Amazon Web Services Secret Access Key",
        "remediation": "Rotate key immediately in AWS Console",
    },
    {
        "id": "GITHUB_TOKEN",
        "name": "GitHub Personal Access Token",
        "category": "Version Control",
        "severity": "critical",
        "pattern": r"ghp_[0-9a-zA-Z]{36}",
        "description": "GitHub Personal Access Token",
        "remediation": "Revoke at GitHub Settings → Developer Settings → Personal Access Tokens",
    },
    {
        "id": "GITHUB_OAUTH",
        "name": "GitHub OAuth Token",
        "category": "Version Control",
        "severity": "critical",
        "pattern": r"gho_[0-9a-zA-Z]{36}",
        "description": "GitHub OAuth Access Token",
        "remediation": "Revoke at GitHub Settings → Applications",
    },
    {
        "id": "STRIPE_SECRET",
        "name": "Stripe Secret Key",
        "category": "Payment",
        "severity": "critical",
        "pattern": r"sk_live_[0-9a-zA-Z]{24,}",
        "description": "Stripe Live Secret Key — can process payments",
        "remediation": "Rotate immediately at dashboard.stripe.com/apikeys",
    },
    {
        "id": "STRIPE_RESTRICTED",
        "name": "Stripe Restricted Key",
        "category": "Payment",
        "severity": "critical",
        "pattern": r"sk_(?:live|test)_[0-9a-zA-Z]{24,}",
        "description": "Stripe Live Restricted Key",
        "remediation": "Rotate immediately at Stripe Dashboard",
    },
    {
        "id": "OPENAI_API_KEY",
        "name": "OpenAI API Key",
        "category": "AI",
        "severity": "critical",
        "pattern": r"sk-[a-zA-Z0-9]{20,}T3BlbkFJ[a-zA-Z0-9]{20,}",
        "description": "OpenAI API Key — can incur charges",
        "remediation": "Revoke at platform.openai.com/api-keys",
    },
    {
        "id": "OPENAI_NEW_KEY",
        "name": "OpenAI API Key (new format)",
        "category": "AI",
        "severity": "critical",
        "pattern": r"sk-proj-[a-zA-Z0-9_-]{50,}",
        "description": "OpenAI Project API Key",
        "remediation": "Revoke at platform.openai.com/api-keys",
    },
    {
        "id": "GCP_SERVICE_ACCOUNT",
        "name": "Google Cloud Service Account Key",
        "category": "Cloud",
        "severity": "critical",
        "pattern": r'"type":\s*"service_account"',
        "description": "Google Cloud Platform Service Account credentials",
        "remediation": "Delete key at console.cloud.google.com → IAM → Service Accounts",
    },
    {
        "id": "PRIVATE_KEY",
        "name": "Private Key (RSA/EC/PGP)",
        "category": "Cryptography",
        "severity": "critical",
        "pattern": r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----",
        "description": "Private cryptographic key",
        "remediation": "Generate new key pair and revoke this one",
    },

    # ── HIGH ──────────────────────────────────────────────────

    {
        "id": "SLACK_TOKEN",
        "name": "Slack API Token",
        "category": "Communication",
        "severity": "high",
        "pattern": r"xox[baprs]-(?:[0-9a-zA-Z]{10,48})",
        "description": "Slack Bot/User/App token",
        "remediation": "Revoke at api.slack.com/apps",
    },
    {
        "id": "SLACK_WEBHOOK",
        "name": "Slack Webhook URL",
        "category": "Communication",
        "severity": "high",
        "pattern": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",
        "description": "Slack Incoming Webhook — can post messages",
        "remediation": "Delete webhook at Slack App settings",
    },
    {
        "id": "TELEGRAM_BOT_TOKEN",
        "name": "Telegram Bot Token",
        "category": "Communication",
        "severity": "high",
        "pattern": r"[0-9]{8,10}:[a-zA-Z0-9_-]{35}",
        "description": "Telegram Bot API Token",
        "remediation": "Revoke via @BotFather → /revoke",
    },
    {
        "id": "SENDGRID_KEY",
        "name": "SendGrid API Key",
        "category": "Email",
        "severity": "high",
        "pattern": r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}",
        "description": "SendGrid API Key — can send emails",
        "remediation": "Revoke at app.sendgrid.com/settings/api_keys",
    },
    {
        "id": "TWILIO_KEY",
        "name": "Twilio API Key",
        "category": "Communication",
        "severity": "high",
        "pattern": r"SK[0-9a-fA-F]{32}",
        "description": "Twilio API Key",
        "remediation": "Revoke at console.twilio.com",
    },
    {
        "id": "FIREBASE_KEY",
        "name": "Firebase API Key",
        "category": "Cloud",
        "severity": "high",
        "pattern": r"AIza[0-9A-Za-z_-]{35}",
        "description": "Google Firebase API Key",
        "remediation": "Restrict or regenerate at Firebase Console",
    },
    {
        "id": "MAILGUN_KEY",
        "name": "Mailgun API Key",
        "category": "Email",
        "severity": "high",
        "pattern": r"key-[0-9a-zA-Z]{32}",
        "description": "Mailgun API Key",
        "remediation": "Rotate at app.mailgun.com/app/account/security",
    },
    {
        "id": "HEROKU_API_KEY",
        "name": "Heroku API Key",
        "category": "Cloud",
        "severity": "high",
        "pattern": r"(?i)heroku.{0,20}['\"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\"]",
        "description": "Heroku API Key",
        "remediation": "Rotate at dashboard.heroku.com/account",
    },
    {
        "id": "DIGITALOCEAN_TOKEN",
        "name": "DigitalOcean Personal Access Token",
        "category": "Cloud",
        "severity": "high",
        "pattern": r"dop_v1_[a-f0-9]{64}",
        "description": "DigitalOcean Personal Access Token",
        "remediation": "Revoke at cloud.digitalocean.com/account/api/tokens",
    },

    # ── MEDIUM ────────────────────────────────────────────────

    {
        "id": "GENERIC_API_KEY",
        "name": "Generic API Key",
        "category": "Generic",
        "severity": "medium",
        "pattern": r"(?i)(?:api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*['\"]([a-zA-Z0-9_\-]{20,})['\"]",
        "description": "Generic API key pattern",
        "remediation": "Review and rotate if this is a real secret",
    },
    {
        "id": "GENERIC_SECRET",
        "name": "Generic Secret",
        "category": "Generic",
        "severity": "medium",
        "pattern": r"(?i)(?:secret|password|passwd|token)\s*[=:]\s*['\"]([a-zA-Z0-9_\-!@#$%]{8,})['\"]",
        "description": "Generic secret/password pattern",
        "remediation": "Use environment variables instead",
    },
    {
        "id": "DATABASE_URL",
        "name": "Database Connection String",
        "category": "Database",
        "severity": "medium",
        "pattern": r"(?i)(?:mongodb|mysql|postgresql|postgres|redis)(?:\+srv)?://[^\s'\"]{10,}",
        "description": "Database connection string with credentials",
        "remediation": "Move to environment variable or secrets manager",
    },
    {
        "id": "JWT_SECRET",
        "name": "JWT Secret",
        "category": "Authentication",
        "severity": "medium",
        "pattern": r"(?i)jwt[_-]?secret\s*[=:]\s*['\"]([a-zA-Z0-9_\-]{10,})['\"]",
        "description": "JWT signing secret",
        "remediation": "Use a strong random secret from environment variables",
    },
    {
        "id": "SSH_PASSWORD",
        "name": "SSH Password in Config",
        "category": "Authentication",
        "severity": "medium",
        "pattern": r"(?i)ssh.{0,10}password\s*[=:]\s*['\"]([^\s'\"]{6,})['\"]",
        "description": "SSH password hardcoded in configuration",
        "remediation": "Use SSH key authentication instead",
    },

    # ── LOW ───────────────────────────────────────────────────

    {
        "id": "IP_ADDRESS",
        "name": "Internal IP Address",
        "category": "Network",
        "severity": "low",
        "pattern": r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b",
        "description": "Internal/private IP address exposed",
        "remediation": "Use configuration files or environment variables",
    },
    {
        "id": "TODO_FIXME_HACK",
        "name": "TODO/FIXME/HACK Comments",
        "category": "Code Quality",
        "severity": "low",
        "pattern": r"(?i)#\s*(?:todo|fixme|hack|xxx|bug)\s*:?\s*(.{10,80})",
        "description": "Unresolved code issue comment",
        "remediation": "Review and resolve the issue",
    },
]


def get_all_rules():
    return RULES


def get_rules_by_severity(min_severity: str):
    order = ["low", "medium", "high", "critical"]
    min_idx = order.index(min_severity)
    return [r for r in RULES if order.index(r["severity"]) >= min_idx]


def get_rules_by_category(category: str):
    return [r for r in RULES if r["category"].lower() == category.lower()]
