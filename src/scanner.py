"""
🔐 Core Scanner Engine
"""

import re
import os
from pathlib import Path
from datetime import datetime
from .rules import get_all_rules, get_rules_by_severity


# File extensions to scan
SCANNABLE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".php", ".rb", ".go", ".java",
    ".cs", ".cpp", ".c", ".h", ".swift", ".kt", ".rs", ".scala",
    ".env", ".cfg", ".config", ".conf", ".ini", ".yaml", ".yml",
    ".json", ".xml", ".toml", ".properties", ".sh", ".bash", ".zsh",
    ".dockerfile", ".tf", ".tfvars", ".hcl", ".sql", ".md", ".txt"
}

# Directories to always skip
DEFAULT_EXCLUDES = {
    ".git", "node_modules", "vendor", "venv", ".venv", "env",
    "__pycache__", ".pytest_cache", "dist", "build", ".next",
    ".nuxt", "coverage", ".coverage", "*.min.js"
}


class Finding:
    """Represents a single secret detection finding."""

    def __init__(self, rule, file_path, line_number, line_content, match):
        self.rule_id = rule["id"]
        self.rule_name = rule["name"]
        self.category = rule["category"]
        self.severity = rule["severity"]
        self.description = rule["description"]
        self.remediation = rule["remediation"]
        self.file_path = str(file_path)
        self.line_number = line_number
        self.line_content = line_content.strip()
        self.match = self._mask_secret(match)
        self.timestamp = datetime.now().isoformat()

    def _mask_secret(self, secret: str) -> str:
        """Partially mask the detected secret."""
        if len(secret) <= 8:
            return "*" * len(secret)
        visible = max(4, len(secret) // 4)
        return secret[:visible] + "*" * (len(secret) - visible * 2) + secret[-visible:]

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "category": self.category,
            "severity": self.severity,
            "description": self.description,
            "remediation": self.remediation,
            "file": self.file_path,
            "line": self.line_number,
            "content": self.line_content,
            "match": self.match,
            "timestamp": self.timestamp,
        }


class SecretsScanner:
    """Main scanner class."""

    def __init__(self):
        self.rules = get_all_rules()
        self._compiled = self._compile_rules()

    def _compile_rules(self) -> list:
        """Pre-compile all regex patterns for performance."""
        compiled = []
        for rule in self.rules:
            try:
                compiled.append({
                    **rule,
                    "regex": re.compile(rule["pattern"], re.MULTILINE | re.IGNORECASE)
                })
            except re.error:
                pass
        return compiled

    def scan_path(self, path: str, exclude: list = None,
                  min_severity: str = None, custom_rules: str = None) -> dict:
        """Scan a file or directory."""
        exclude = set(exclude or []) | DEFAULT_EXCLUDES
        rules = get_rules_by_severity(min_severity) if min_severity else self.rules

        path_obj = Path(path)
        findings = []
        scanned_files = 0
        skipped_files = 0

        if path_obj.is_file():
            file_findings = self._scan_file(path_obj, rules)
            findings.extend(file_findings)
            scanned_files = 1
        elif path_obj.is_dir():
            for file_path in path_obj.rglob("*"):
                if self._should_skip(file_path, exclude):
                    skipped_files += 1
                    continue
                if file_path.is_file() and file_path.suffix.lower() in SCANNABLE_EXTENSIONS:
                    file_findings = self._scan_file(file_path, rules)
                    findings.extend(file_findings)
                    scanned_files += 1

        return self._build_report(findings, scanned_files, skipped_files, str(path))

    def _scan_file(self, file_path: Path, rules: list = None) -> list:
        """Scan a single file for secrets."""
        findings = []
        rules = rules or self._compiled

        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            lines = content.splitlines()

            for rule in rules:
                regex = re.compile(rule["pattern"], re.MULTILINE | re.IGNORECASE)
                for match in regex.finditer(content):
                    line_num = content[:match.start()].count("\n") + 1
                    line_content = lines[line_num - 1] if line_num <= len(lines) else ""

                    # Skip if it looks like a placeholder
                    matched_text = match.group(0)
                    if self._is_placeholder(matched_text):
                        continue

                    findings.append(Finding(
                        rule=rule,
                        file_path=file_path,
                        line_number=line_num,
                        line_content=line_content,
                        match=matched_text
                    ))
        except (PermissionError, OSError):
            pass

        return findings

    def _is_placeholder(self, text: str) -> bool:
        """Check if the match looks like a placeholder, not a real secret."""
        placeholders = [
            "your-", "your_", "xxx", "example", "placeholder",
            "changeme", "replace", "insert", "todo", "fixme",
            "xxxxxxxx", "00000000", "test", "dummy", "fake",
            "sample", "demo", "<", ">", "${", "%(", "env."
        ]
        text_lower = text.lower()
        return any(p in text_lower for p in placeholders)

    def _should_skip(self, path: Path, exclude: set) -> bool:
        """Check if path should be skipped."""
        parts = set(path.parts)
        return bool(parts & exclude) or any(
            exc in str(path) for exc in exclude if "/" in exc or "\\" in exc
        )

    def scan_git_history(self, commits: int = 20, branch: str = "HEAD") -> dict:
        """Scan git commit history for secrets."""
        import subprocess
        findings = []

        try:
            result = subprocess.run(
                ["git", "log", f"-{commits}", "--pretty=format:%H|%s|%ai", branch],
                capture_output=True, text=True, timeout=30
            )

            commit_lines = result.stdout.strip().split("\n")

            for commit_line in commit_lines:
                if not commit_line:
                    continue
                parts = commit_line.split("|", 2)
                if len(parts) < 1:
                    continue

                commit_hash = parts[0]
                diff_result = subprocess.run(
                    ["git", "show", "--stat", commit_hash],
                    capture_output=True, text=True, timeout=30
                )

                for rule in self._compiled:
                    for match in rule["regex"].finditer(diff_result.stdout):
                        if not self._is_placeholder(match.group(0)):
                            findings.append({
                                "commit": commit_hash[:8],
                                "rule_name": rule["name"],
                                "severity": rule["severity"],
                                "match": match.group(0)[:50] + "...",
                            })

        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        return {"findings": findings, "total_found": len(findings), "type": "git"}

    def get_rules(self, category: str = None) -> list:
        """Get all rules, optionally filtered by category."""
        if category:
            return [r for r in self.rules if r["category"].lower() == category.lower()]
        return self.rules

    def _build_report(self, findings: list, scanned: int, skipped: int, path: str) -> dict:
        """Build the final report dictionary."""
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings:
            severity_counts[f.severity] += 1

        return {
            "scan_path": path,
            "timestamp": datetime.now().isoformat(),
            "total_found": len(findings),
            "scanned_files": scanned,
            "skipped_files": skipped,
            "severity_breakdown": severity_counts,
            "findings": [f.to_dict() for f in findings],
        }
