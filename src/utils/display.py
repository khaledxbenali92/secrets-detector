"""
Display utilities
"""

BOLD = "\033[1m"
RESET = "\033[0m"
GREEN = "\033[92m"
RED = "\033[91m"
CYAN = "\033[96m"


def print_banner():
    print(f"""{CYAN}{BOLD}
╔══════════════════════════════════════════════════════════╗
║           🔐 Secrets Detector v1.0                       ║
║     Find hardcoded secrets before attackers do           ║
║           github.com/khaledxbenali92                     ║
╚══════════════════════════════════════════════════════════╝
{RESET}""")


def print_summary(results: dict):
    total = results.get("total_found", 0)
    scanned = results.get("scanned_files", 0)
    breakdown = results.get("severity_breakdown", {})

    print(f"\n{'─'*50}")
    print(f"{BOLD}📊 SCAN SUMMARY{RESET}")
    print(f"{'─'*50}")
    print(f"Files scanned:  {scanned}")
    print(f"Total findings: {BOLD}{total}{RESET}")

    if total > 0:
        print(f"\nBreakdown:")
        if breakdown.get("critical"):
            print(f"  🔴 Critical: {breakdown['critical']}")
        if breakdown.get("high"):
            print(f"  🟠 High:     {breakdown['high']}")
        if breakdown.get("medium"):
            print(f"  🟡 Medium:   {breakdown['medium']}")
        if breakdown.get("low"):
            print(f"  🟢 Low:      {breakdown['low']}")
        print(f"\n{RED}⚠️  Secrets found! Fix before committing.{RESET}")
    else:
        print(f"\n{GREEN}✅ Clean! No secrets detected.{RESET}")
    print(f"{'─'*50}\n")
