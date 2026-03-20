"""
🔐 Secrets Detector — Main CLI Entry Point
Detect hardcoded secrets, API keys, and credentials in your codebase
"""

import sys
import argparse
from src.scanner import SecretsScanner
from src.reporters.console import ConsoleReporter
from src.reporters.json_reporter import JSONReporter
from src.reporters.html_reporter import HTMLReporter
from src.utils.display import print_banner, print_summary


def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="🔐 Secrets Detector — Find hardcoded secrets before attackers do",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  secrets-detector scan --path ./my-project
  secrets-detector scan --path ./src --format json --output report.json
  secrets-detector scan --path . --severity high --format html
  secrets-detector scan --path . --exclude tests/ --exclude node_modules/
  secrets-detector git --commits 50
        """
    )

    subparsers = parser.add_subparsers(dest="command")

    # ── SCAN command ──────────────────────────────────────────
    scan_parser = subparsers.add_parser("scan", help="Scan files or directory for secrets")
    scan_parser.add_argument("--path", type=str, default=".", help="Path to scan (file or directory)")
    scan_parser.add_argument("--format", choices=["console", "json", "html"], default="console", help="Output format")
    scan_parser.add_argument("--output", type=str, help="Output file path (for json/html)")
    scan_parser.add_argument("--severity", choices=["low", "medium", "high", "critical"], help="Minimum severity level")
    scan_parser.add_argument("--exclude", action="append", default=[], help="Paths to exclude (can be used multiple times)")
    scan_parser.add_argument("--no-git", action="store_true", help="Skip .git directory")
    scan_parser.add_argument("--rules", type=str, help="Path to custom rules file (JSON)")

    # ── GIT command ───────────────────────────────────────────
    git_parser = subparsers.add_parser("git", help="Scan git commit history for secrets")
    git_parser.add_argument("--commits", type=int, default=20, help="Number of commits to scan")
    git_parser.add_argument("--branch", type=str, default="HEAD", help="Branch to scan")
    git_parser.add_argument("--format", choices=["console", "json", "html"], default="console")
    git_parser.add_argument("--output", type=str, help="Output file path")

    # ── RULES command ─────────────────────────────────────────
    rules_parser = subparsers.add_parser("rules", help="List all detection rules")
    rules_parser.add_argument("--category", type=str, help="Filter by category")

    # ── AUDIT command ─────────────────────────────────────────
    audit_parser = subparsers.add_parser("audit", help="Full security audit with recommendations")
    audit_parser.add_argument("--path", type=str, default=".", help="Path to audit")
    audit_parser.add_argument("--output", type=str, default="security_audit.html", help="Output file")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    scanner = SecretsScanner()

    if args.command == "scan":
        _run_scan(scanner, args)
    elif args.command == "git":
        _run_git_scan(scanner, args)
    elif args.command == "rules":
        _show_rules(scanner, args)
    elif args.command == "audit":
        _run_audit(scanner, args)


def _run_scan(scanner, args):
    """Run file/directory scan."""
    print(f"\n🔍 Scanning: {args.path}\n")

    results = scanner.scan_path(
        path=args.path,
        exclude=args.exclude,
        min_severity=args.severity,
        custom_rules=args.rules
    )

    reporter = _get_reporter(args.format, args.output)
    reporter.report(results)
    print_summary(results)

    # Exit with error code if secrets found (useful for CI/CD)
    if results.get("total_found", 0) > 0:
        sys.exit(1)


def _run_git_scan(scanner, args):
    """Scan git history."""
    print(f"\n📜 Scanning last {args.commits} commits...\n")
    results = scanner.scan_git_history(commits=args.commits, branch=args.branch)
    reporter = _get_reporter(args.format, args.output)
    reporter.report(results)
    print_summary(results)


def _show_rules(scanner, args):
    """Display all detection rules."""
    rules = scanner.get_rules(category=args.category)
    print(f"\n📋 Detection Rules ({len(rules)} total)\n")
    print(f"{'Category':<20} {'Rule Name':<35} {'Severity':<10}")
    print("-" * 65)
    for rule in rules:
        severity_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(rule["severity"], "⚪")
        print(f"{rule['category']:<20} {rule['name']:<35} {severity_icon} {rule['severity']}")


def _run_audit(scanner, args):
    """Full security audit."""
    print(f"\n🛡️  Running full security audit on: {args.path}\n")
    results = scanner.scan_path(path=args.path)
    reporter = HTMLReporter(args.output)
    reporter.report(results)
    print(f"\n✅ Audit report saved to: {args.output}")


def _get_reporter(format_type, output_path):
    """Get the appropriate reporter."""
    if format_type == "json":
        return JSONReporter(output_path)
    elif format_type == "html":
        return HTMLReporter(output_path)
    return ConsoleReporter()


if __name__ == "__main__":
    main()
