"""
JSON Reporter
"""

import json
from pathlib import Path


class JSONReporter:

    def __init__(self, output_path: str = None):
        self.output_path = output_path or "secrets-report.json"

    def report(self, results: dict):
        Path(self.output_path).write_text(
            json.dumps(results, indent=2, ensure_ascii=False),
            encoding="utf-8"
        )
        print(f"\n✅ JSON report saved to: {self.output_path}")
        print(f"📊 Total findings: {results.get('total_found', 0)}")
