#!/usr/bin/env python3
"""Resume arquivos .trx (MSTest/VSTest) em Markdown para o GITHUB_STEP_SUMMARY.

Uso: trx_summary.py <diretório com .trx>
Falha (exit 1) se nenhum .trx for encontrado, para não mascarar uma execução de testes que não aconteceu.
"""
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

NS = {"t": "http://microsoft.com/schemas/VisualStudio/TeamTest/2010"}


def summarize(path: Path) -> tuple[dict, list[str]]:
    root = ET.parse(path).getroot()
    counters = root.find(".//t:ResultSummary/t:Counters", NS)
    stats = {k: int(counters.get(k, "0")) for k in ("total", "passed", "failed", "executed", "notExecuted")} if counters is not None else {}
    failed = [
        r.get("testName", "?")
        for r in root.findall(".//t:UnitTestResult", NS)
        if r.get("outcome") == "Failed"
    ]
    return stats, failed


def main() -> int:
    directory = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("test-results")
    files = sorted(directory.rglob("*.trx"))
    print("## Test results\n")
    if not files:
        print("No `.trx` files were produced.")
        return 1

    print("| Suite | Total | Passed | Failed |")
    print("|---|---:|---:|---:|")
    all_failed: list[str] = []
    for f in files:
        stats, failed = summarize(f)
        print(f"| {f.stem} | {stats.get('total', '?')} | {stats.get('passed', '?')} | {stats.get('failed', '?')} |")
        all_failed.extend(failed)

    if all_failed:
        print("\n### Failed tests\n")
        for name in all_failed[:50]:
            print(f"- `{name}`")
    return 0


if __name__ == "__main__":
    sys.exit(main())
