"""
WDash Advisor — Elasticsearch configuration review.

It works in two stages:

    snapshot = collect(es)          # I/O: gather raw data from the cluster
    report   = run_rules(snapshot)  # pure: run the rules over the snapshot

The split is deliberate. Because rules never see a live connection they can be
tested against a saved snapshot, they are deterministic, and they port cleanly
to another language.

Usage:
    from wdash.advisor import analyze
    report = analyze(es)              # an elasticsearch.Elasticsearch
    print(report.to_dict())
"""

from .models import (Finding, NotEvaluated, Report, Rule, Severity, all_rules, rule,
                     run_rules)
from .snapshot import ClusterSnapshot, collect

__all__ = [
    "analyze",
    "collect",
    "run_rules",
    "all_rules",
    "ClusterSnapshot",
    "NotEvaluated",
    "Report",
    "Finding",
    "Rule",
    "Severity",
    "rule",
]


def analyze(es, timeout=30):
    """Collect a snapshot from the cluster, run the rules, return a Report."""
    return run_rules(collect(es, timeout=timeout))
