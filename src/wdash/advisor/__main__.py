"""
Run the Advisor from the command line.

    python -m wdash.advisor --url http://localhost:9200
    python -m wdash.advisor --save-snapshot tests/fixtures/lab.json
    python -m wdash.advisor --from-snapshot tests/fixtures/lab.json --json

With --from-snapshot no live cluster is needed; the rules run against a saved
snapshot. That is the fastest loop while developing rules.

The exit status, for CI: 0 when there is nothing to report, 1 when --fail-on
names a level and a finding at or above it exists, and 2 when the report
cannot say — nothing could be evaluated, or with --fail-on, anything was not
collected or not evaluated. A gate that passes when it could not look is not
a gate.

The cluster's certificate is checked, against ELASTICSEARCH_CA_CERTS when it
is set; ELASTICSEARCH_VERIFY_CERTS=false or --insecure turns that off.
ELASTICSEARCH_USERNAME and ELASTICSEARCH_PASSWORD go to the cluster, and
without the check they go to whoever answers.
"""

import argparse
import json
import os
import sys

from . import run_rules
from .models import Severity
from .snapshot import ClusterSnapshot, collect

#: How the certificate switch is spelled, read as a tri-state. Anything
#: that is neither a yes nor a no keeps the check and says so on stderr:
#: the cost of misreading the word is a password sent to whoever answered,
#: and that cannot be taken back.
VERIFY_YES = frozenset({"true", "1", "yes", "on"})
VERIFY_NO = frozenset({"false", "0", "no", "off"})

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
    if report.score is None:
        print(paint("  score      : n/a — nothing could be evaluated",
                    COLORS[Severity.CRITICAL]))
    else:
        print(f"  score      : {report.score}/100")
    print(f"  findings   : {counts['critical']} critical, "
          f"{counts['warning']} warning, {counts['info']} info")
    print(f"  passed     : {len(report.passed)} rules")
    if report.not_evaluated:
        print(paint(f"  not evaluated: {len(report.not_evaluated)} rules",
                    COLORS[Severity.WARNING]))
    if report.skipped:
        print(f"  skipped    : {len(report.skipped)} rules")
    if report.errors:
        print(paint(f"  rule errors: {len(report.errors)}", COLORS[Severity.CRITICAL]))
    if report.collection_errors:
        print(paint(f"  collection errors: {', '.join(report.collection_errors)}",
                    COLORS[Severity.WARNING]))
    print()

    if not report.findings:
        if report.unavailable:
            print("  Nothing could be evaluated: none of what the rules read "
                  "was collected.")
        elif report.complete:
            print("  No findings.")
        else:
            print(f"  No findings among the {report.evaluated} rules that could "
                  f"look. The rest could not; see below.")
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

    if report.not_evaluated:
        print(paint("Rules that could not be evaluated", BOLD))
        for rule_id, title, reason in report.not_evaluated:
            print(f"  {rule_id}  {title} — {reason}")
        print()

    if report.errors:
        print(paint("Rules that failed to run", BOLD))
        for rule_id, error in report.errors:
            print(f"  {rule_id}: {error}")
        print()


def _client_config(args, environ):
    """What `ElasticsearchClient` reads, from the variables the web process
    reads.

    It hard-coded `verify_certs=False` and ignored ELASTICSEARCH_VERIFY_CERTS
    and ELASTICSEARCH_CA_CERTS, so ELASTICSEARCH_PASSWORD went to any
    certificate at all. Verification is on here unless one of them says
    otherwise: the web process defaults to off so that an upgrade does not
    cut a deployment off from its cluster, but this is run by hand or in CI,
    where a refused certificate is a message, and a password sent to whoever
    answered cannot be taken back.
    """
    written = (environ.get("ELASTICSEARCH_VERIFY_CERTS") or "").strip()
    spelled = written.lower()
    # Only "true" counted as yes, so `=1`, `=yes` and `=on` — how most
    # people write "on" — turned the check OFF and sent the password to
    # whatever certificate answered. An operator who wrote `=1` meaning
    # "verify" ended up worse off than one who set nothing at all.
    verify = spelled not in VERIFY_NO
    if written and spelled not in VERIFY_YES and spelled not in VERIFY_NO:
        print(f"wdash.advisor: ELASTICSEARCH_VERIFY_CERTS={written!r} is "
              f"neither a yes nor a no; the certificate is checked",
              file=sys.stderr)
    # TLS options and a plain-http host are refused by the transport, so a
    # CA named for an https cluster stopped an http one being read at all.
    https = str(args.url or "").strip().lower().startswith("https://")
    return {
        "ELASTICSEARCH_URL": args.url,
        "ELASTICSEARCH_USERNAME": environ.get("ELASTICSEARCH_USERNAME"),
        "ELASTICSEARCH_PASSWORD": environ.get("ELASTICSEARCH_PASSWORD"),
        "ELASTICSEARCH_TIMEOUT": 30,
        "ELASTICSEARCH_VERIFY_CERTS": verify and not args.insecure,
        "ELASTICSEARCH_CA_CERTS": (
            environ.get("ELASTICSEARCH_CA_CERTS") or None) if https else None,
    }


def _explain(report, headline):
    """Why the exit status is 2, on stderr so --json stays parseable."""
    print(f"wdash.advisor: {headline}", file=sys.stderr)
    for name, error in report.collection_errors.items():
        print(f"  {name} was not collected: {error}", file=sys.stderr)
    if report.not_evaluated:
        print(f"  {len(report.not_evaluated)} rules could not be evaluated",
              file=sys.stderr)
    for rule_id, error in report.errors:
        print(f"  {rule_id} failed to run: {error}", file=sys.stderr)
    if any("CERTIFICATE_VERIFY_FAILED" in str(error)
           for error in report.collection_errors.values()):
        print("  The cluster's certificate is not trusted. Point "
              "ELASTICSEARCH_CA_CERTS at the CA that signed it, or pass "
              "--insecure to skip the check; the credentials then go to "
              "whoever answers.", file=sys.stderr)


def _exit_status(report, fail_on):
    if report.unavailable:
        _explain(report, "nothing could be evaluated")
        return 2
    if fail_on:
        threshold = Severity(fail_on).weight
        if any(f.severity.weight >= threshold for f in report.findings):
            return 1
        if not report.complete:
            _explain(report, f"no finding at {fail_on} or above among the rules "
                             f"that ran, but the report is incomplete")
            return 2
    return 0


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
                        help="exit 1 when a finding at this level exists, and 2 "
                             "when the report is incomplete (for CI)")
    parser.add_argument("--insecure", action="store_true",
                        help="do not check the cluster's certificate; the "
                             "credentials then go to whoever answers")
    args = parser.parse_args(argv)

    if args.from_snapshot:
        snapshot = ClusterSnapshot.load(args.from_snapshot)
    else:
        try:
            from ..logs.elasticsearch_client import ElasticsearchClient
        except ImportError:
            sys.exit("the elasticsearch library is required: "
                     "pip install 'elasticsearch>=8,<9'")

        config = _client_config(args, os.environ)
        if not config["ELASTICSEARCH_VERIFY_CERTS"]:
            print("wdash.advisor: the cluster's certificate is not checked",
                  file=sys.stderr)
        try:
            snapshot = collect(ElasticsearchClient(config).es)
        except Exception as exc:
            # 2, not sys.exit's 1: that is the status for "findings", and a
            # gate reading it would blame the cluster for a wrong URL.
            print(f"could not collect a snapshot from {args.url}: {exc}",
                  file=sys.stderr)
            return 2

    if args.save_snapshot:
        snapshot.save(args.save_snapshot)
        print(f"Snapshot written to {args.save_snapshot}", file=sys.stderr)

    report = run_rules(snapshot)

    if args.json:
        print(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
    else:
        print_report(report, use_color=not args.no_color, show_passed=args.show_passed)

    return _exit_status(report, args.fail_on)


if __name__ == "__main__":
    sys.exit(main())
