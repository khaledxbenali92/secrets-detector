"""
Console Reporter — Colored terminal output
"""


SEVERITY_COLORS = {
    "critical": "\033[91m",  # Red
    "high":     "\033[93m",  # Yellow
    "medium":   "\033[94m",  # Blue
    "low":      "\033[92m",  # Green
}
RESET = "\033[0m"
BOLD  = "\033[1m"

SEVERITY_ICONS = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🟢",
}


class ConsoleReporter:

    def report(self, results: dict):
        findings = results.get("findings", [])

        if not findings:
            print(f"\n{BOLD}✅ No secrets detected!{RESET}\n")
            return

        # Group by severity
        by_severity = {"critical": [], "high": [], "medium": [], "low": []}
        for f in findings:
            by_severity[f["severity"]].append(f)

        for severity in ["critical", "high", "medium", "low"]:
            items = by_severity[severity]
            if not items:
                continue

            color = SEVERITY_COLORS[severity]
            icon = SEVERITY_ICONS[severity]
            print(f"\n{color}{BOLD}{icon} {severity.upper()} ({len(items)} found){RESET}")
            print("─" * 60)

            for f in items:
                print(f"{BOLD}Rule:{RESET}     {f['rule_name']}")
                print(f"{BOLD}File:{RESET}     {f['file']}:{f['line']}")
                print(f"{BOLD}Match:{RESET}    {color}{f['match']}{RESET}")
                print(f"{BOLD}Fix:{RESET}      {f['remediation']}")
                print()
