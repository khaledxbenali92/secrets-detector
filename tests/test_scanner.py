"""
🔐 Tests for SecretsScanner
"""

import pytest
from src.scanner import SecretsScanner
from src.rules import get_all_rules, get_rules_by_severity


# ── Rules Tests ────────────────────────────────────────────────────────────────

def test_rules_loaded():
    rules = get_all_rules()
    assert len(rules) > 0


def test_rules_have_required_fields():
    rules = get_all_rules()
    required = {"id", "name", "category", "severity", "pattern", "description", "remediation"}
    for rule in rules:
        assert required.issubset(rule.keys()), f"Rule {rule.get('id')} missing fields"


def test_severity_filter():
    high_and_above = get_rules_by_severity("high")
    for rule in high_and_above:
        assert rule["severity"] in ("high", "critical")


# ── Scanner Init ───────────────────────────────────────────────────────────────

def test_scanner_initializes():
    scanner = SecretsScanner()
    assert scanner is not None
    assert len(scanner.rules) > 0


# ── Detection Tests ────────────────────────────────────────────────────────────

def test_detects_aws_key(tmp_path):
    """AWS pattern: AKIA + 16 uppercase alphanumeric chars."""
    scanner = SecretsScanner()
    test_file = tmp_path / "config.py"
    # Build at runtime to avoid GitHub Secret Scanning
    prefix = "AKIA"
    fake_key = prefix + "IOSFODNN7EXAMPLF"
    test_file.write_text(f'AWS_KEY = "{fake_key}"\n')
    results = scanner.scan_path(str(tmp_path))
    assert results["total_found"] > 0


def test_detects_github_token(tmp_path):
    """GitHub token pattern: ghp_[0-9a-zA-Z]{36}"""
    scanner = SecretsScanner()
    test_file = tmp_path / "config.py"
    test_file.write_text('GITHUB_TOKEN = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890"\n')
    results = scanner.scan_path(str(tmp_path))
    assert results["total_found"] > 0


def test_detects_stripe_key(tmp_path):
    """Stripe pattern: sk_(?:live|test)_[0-9a-zA-Z]{24,}"""
    scanner = SecretsScanner()
    test_file = tmp_path / "payment.py"
    # Build at runtime to avoid GitHub Secret Scanning
    prefix = "sk_" + "live" + "_"
    fake_key = prefix + "abcdefghijklmnopqrstuvwx"
    test_file.write_text(f'payment_token = "{fake_key}"\n')
    results = scanner.scan_path(str(tmp_path))
    assert results["total_found"] > 0


# ── Placeholder Ignoring ───────────────────────────────────────────────────────

def test_ignores_placeholders(tmp_path):
    scanner = SecretsScanner()
    test_file = tmp_path / "readme.py"
    test_file.write_text('AWS_KEY = "AKIA_YOUR_ACCESS_KEY_HERE"\n')
    results = scanner.scan_path(str(tmp_path))
    assert results["total_found"] == 0


# ── Clean Directory ────────────────────────────────────────────────────────────

def test_clean_directory(tmp_path):
    scanner = SecretsScanner()
    test_file = tmp_path / "clean.py"
    test_file.write_text('print("Hello, world!")\nx = 42\n')
    results = scanner.scan_path(str(tmp_path))
    assert results["total_found"] == 0


# ── Report Structure ───────────────────────────────────────────────────────────

def test_report_structure(tmp_path):
    scanner = SecretsScanner()
    test_file = tmp_path / "empty.py"
    test_file.write_text("")
    results = scanner.scan_path(str(tmp_path))

    assert "total_found" in results
    assert "scanned_files" in results
    assert "skipped_files" in results
    assert "severity_breakdown" in results
    assert "findings" in results
    assert "scan_path" in results
    assert "timestamp" in results


# ── Secret Masking ─────────────────────────────────────────────────────────────

def test_secret_masking(tmp_path):
    scanner = SecretsScanner()
    test_file = tmp_path / "config.py"
    test_file.write_text('GITHUB_TOKEN = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890"\n')
    results = scanner.scan_path(str(tmp_path))

    assert results["total_found"] > 0
    for finding in results["findings"]:
        # The masked secret should contain asterisks
        assert "*" in finding["match"]
        # The original full token should NOT appear unmasked
        assert "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890" not in finding["match"]
