"""
Run the Advisor from the command line.

    python -m wdash.advisor --url http://localhost:9200
    python -m wdash.advisor --save-snapshot tests/fixtures/lab.json
    python -m wdash.advisor --from-snapshot tests/fixtures/lab.json --json

With --from-snapshot no live cluster is needed; the rules run against a saved
snapshot. That is the fastest loop while developing rules.
"""

import argparse
import json
import os
import sys

from . import run_rules
from .models import Severity
from .snapshot import ClusterSnapshot, collect

COLORS = {
    Severity.CRITICAL: "\033[91m",
    Severity.WARNING: "\033[93m",
    Severity.INFO: "\033[96m",
}
RESET = "\033[0m"
BOLD = "\033[1m"

LABELS = {
    Severity.CRITICAL: "CRITICAL",
    Severity.WARNING: "WARNING",
    Severity.INFO: "INFO",
}


def _wrap(text, width, indent):
    words, lines, current = text.split(), [], ""
    for word in words:
        if len(current) + len(word) + 1 > width:
            lines.append(current)
            current = word
        else:
            current = f"{current} {word}".strip()
    if current:
        lines.append(current)
    return f"\n{indent}".join(lines)


def print_report(report, use_color=True, show_passed=False):
    def paint(text, code):
        return f"{code}{text}{RESET}" if use_color else text

    counts = report.counts
    print()
    print(paint(f"Elasticsearch Advisor — {report.cluster_name}", BOLD))
    print(f"  version    : {report.version} ({report.distribution})")
    print(f"  taken at   : {report.taken_at}")
    print(f"  score      : {report.score}/100")
    print(f"  findings   : {counts['critical']} critical, "
          f"{counts['warning']} warning, {counts['info']} info")
    print(f"  passed     : {len(report.passed)} rules")
    if report.skipped:
        print(f"  skipped    : {len(report.skipped)} rules")
    if report.errors:
        print(paint(f"  rule errors: {len(report.errors)}", COLORS[Severity.CRITICAL]))
    if report.collection_errors:
        print(paint(f"  collection errors: {', '.join(report.collection_errors)}",
                    COLORS[Severity.WARNING]))
    print()

    if not report.findings:
        print("  No findings.")
        print()

    for finding in report.findings:
        color = COLORS[finding.severity]
        label = LABELS[finding.severity]
        print(f"{paint(f'[{label}]', color)} {paint(finding.rule_id, BOLD)} "
              f"{finding.title}")
        print(f"    Observed : {_wrap(finding.evidence, 76, '               ')}")
        print(f"    Impact   : {_wrap(finding.impact, 76, '               ')}")
        print(f"    Fix      : {_wrap(finding.remediation, 76, '               ')}")
        if finding.targets:
            shown = ", ".join(finding.targets[:6])
            extra = f" (+{len(finding.targets) - 6})" if len(finding.targets) > 6 else ""
            print(f"    Affected : {shown}{extra}")
        print()

    if show_passed and report.passed:
        print(paint("Passed rules", BOLD))
        for rule_id, title in report.passed:
            print(f"  [OK] {rule_id}  {title}")
        print()

    if report.errors:
        print(paint("Rules that failed to run", BOLD))
        for rule_id, error in report.errors:
            print(f"  {rule_id}: {error}")
        print()


def main(argv=None):
    parser = argparse.ArgumentParser(prog="wdash.advisor",
                                     description="Elasticsearch configuration review")
    parser.add_argument("--url", default=os.environ.get("ELASTICSEARCH_URL",
                                                        "http://localhost:9200"))
    parser.add_argument("--from-snapshot",
                        help="use a saved snapshot instead of a live cluster")
    parser.add_argument("--save-snapshot", help="write the collected snapshot to this file")
    parser.add_argument("--json", action="store_true", help="emit the report as JSON")
    parser.add_argument("--show-passed", action="store_true", help="also list passing rules")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--fail-on", choices=["critical", "warning", "info"],
                        help="exit 1 when a finding at this level exists (for CI)")
    args = parser.parse_args(argv)

    if args.from_snapshot:
        snapshot = ClusterSnapshot.load(args.from_snapshot)
    else:
        try:
            from elasticsearch import Elasticsearch
        except ImportError:
            sys.exit("the elasticsearch library is required: "
                     "pip install 'elasticsearch>=8,<9'")

        kwargs = {"hosts": [args.url], "verify_certs": False, "request_timeout": 30}
        user = os.environ.get("ELASTICSEARCH_USERNAME")
        password = os.environ.get("ELASTICSEARCH_PASSWORD")
        if user and password:
            kwargs["basic_auth"] = (user, password)
        try:
            snapshot = collect(Elasticsearch(**kwargs))
        except Exception as exc:
            sys.exit(f"could not collect a snapshot from {args.url}: {exc}")

    if args.save_snapshot:
        snapshot.save(args.save_snapshot)
        print(f"Snapshot written to {args.save_snapshot}", file=sys.stderr)

    report = run_rules(snapshot)

    if args.json:
        print(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
    else:
        print_report(report, use_color=not args.no_color, show_passed=args.show_passed)

    if args.fail_on:
        threshold = Severity(args.fail_on).weight
        if any(f.severity.weight >= threshold for f in report.findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
