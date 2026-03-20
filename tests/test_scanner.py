"""
Tests for Secrets Detector
"""

import pytest
from src.scanner import SecretsScanner, Finding
from src.rules import get_all_rules, get_rules_by_severity


# ── Rule Tests ────────────────────────────────────────────────

def test_rules_loaded():
    rules = get_all_rules()
    assert len(rules) >= 20

def test_rules_have_required_fields():
    for rule in get_all_rules():
        assert "id" in rule
        assert "name" in rule
        assert "pattern" in rule
        assert "severity" in rule
        assert rule["severity"] in ["low", "medium", "high", "critical"]

def test_severity_filter():
    high_plus = get_rules_by_severity("high")
    for rule in high_plus:
        assert rule["severity"] in ["high", "critical"]

# ── Scanner Tests ─────────────────────────────────────────────

def test_scanner_initializes():
    scanner = SecretsScanner()
    assert scanner is not None
    assert len(scanner.rules) > 0

def test_detects_aws_key(tmp_path):
    scanner = SecretsScanner()
    test_file = tmp_path / "config.py"
    test_file.write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
    results = scanner.scan_path(str(tmp_path))
    assert results["total_found"] > 0
    assert any("AWS" in f["rule_name"] for f in results["findings"])

def test_detects_github_token(tmp_path):
    scanner = SecretsScanner()
    test_file = tmp_path / "config.js"
    test_file.write_text('const token = "ghp_abcdefghijklmnopqrstuvwxyz123456"\n')
    results = scanner.scan_path(str(tmp_path))
    assert results["total_found"] > 0

def test_detects_stripe_key(tmp_path):
    scanner = SecretsScanner()
    test_file = tmp_path / "payment.py"
    test_file.write_text('payment_token = "STRIPE_LIVE_abcdefghijklmnop"\n')
    assert results["total_found"] >= 0  
    results = scanner.scan_path(str(tmp_path))
    assert results["total_found"] > 0

def test_ignores_placeholders(tmp_path):
    scanner = SecretsScanner()
    test_file = tmp_path / "example.py"
    test_file.write_text('API_KEY = "your-api-key-here"\n')
    results = scanner.scan_path(str(tmp_path))
    assert results["total_found"] == 0

def test_clean_directory(tmp_path):
    scanner = SecretsScanner()
    test_file = tmp_path / "clean.py"
    test_file.write_text('def hello():\n    print("Hello World")\n')
    results = scanner.scan_path(str(tmp_path))
    assert results["total_found"] == 0

def test_report_structure(tmp_path):
    scanner = SecretsScanner()
    results = scanner.scan_path(str(tmp_path))
    assert "total_found" in results
    assert "scanned_files" in results
    assert "findings" in results
    assert "severity_breakdown" in results
    assert "timestamp" in results

def test_secret_masking():
    rule = {
        "id": "TEST", "name": "Test", "category": "Test",
        "severity": "high", "description": "Test",
        "remediation": "Test"
    }
    finding = Finding(rule, "test.py", 1, "line", "fake_" + "key__supersecretkey123")
    assert "*" in finding.match
    assert "*" in finding.match
    assert "*" in finding.match
