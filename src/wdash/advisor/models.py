"""
Advisor core models.

Design rule: this module and the rules never touch Elasticsearch. Rules are
pure functions over a ClusterSnapshot, which means:

  - tests need no live cluster (a saved JSON fixture is enough)
  - rules are deterministic
  - they map one to one onto a Rule struct with a func field in any language
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Callable, Iterable, Optional


class Severity(str, Enum):
    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"

    @property
    def weight(self):
        return {"critical": 3, "warning": 2, "info": 1}[self.value]


@dataclass
class Finding:
    """A single finding.

    `evidence` carries the actual observed values — without them nobody trusts
    the finding. `remediation` must be concrete; advice like "review this" is
    useless.
    """
    rule_id: str
    category: str
    severity: Severity
    title: str
    evidence: str
    impact: str
    remediation: str
    targets: list = field(default_factory=list)   # affected index / node names
    docs_url: Optional[str] = None

    def to_dict(self):
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class Rule:
    id: str
    category: str
    title: str
    check: Callable
    # Applicability constraints. In a multi-backend setup the same rule is not
    # valid everywhere (ILM is Elasticsearch-specific; OpenSearch uses ISM).
    min_version: Optional[tuple] = None
    max_version: Optional[tuple] = None
    distributions: Optional[tuple] = None   # None = every distribution
    #: Which backends this rule can be evaluated against. Defaults to
    #: Elasticsearch because that is what every rule written before the
    #: Advisor grew a second backend assumes — a shard count means nothing to
    #: Loki, and running it there would produce a finding about a concept the
    #: operator does not have.
    backends: tuple = ("elasticsearch",)

    def applies_to(self, snapshot):
        backend = getattr(snapshot, "backend", "elasticsearch")
        if backend not in self.backends:
            return False, f"not a {backend} rule"
        if self.distributions and snapshot.distribution not in self.distributions:
            return False, f"not supported on {snapshot.distribution}"
        version = snapshot.version_tuple
        if self.min_version and version < self.min_version:
            return False, f"requires at least {'.'.join(map(str, self.min_version))}"
        if self.max_version and version > self.max_version:
            return False, f"supported up to {'.'.join(map(str, self.max_version))}"
        return True, None


# --------------------------------------------------------------------------
# Registry
# --------------------------------------------------------------------------

_REGISTRY = []


def rule(id, category, title, min_version=None, max_version=None,
         distributions=None, backends=("elasticsearch",)):
    """Decorator that adds a rule function to the registry.

    The decorated function takes a snapshot and yields Findings.
    """
    def decorator(fn):
        _REGISTRY.append(Rule(
            id=id,
            category=category,
            title=title,
            check=fn,
            min_version=min_version,
            max_version=max_version,
            distributions=distributions,
            backends=tuple(backends),
        ))
        return fn
    return decorator


def all_rules(backend=None):
    """Every registered rule, ordered by id.

    `backend` narrows to the rules that can be evaluated against it. Without
    it the whole registry comes back, which is what the rule-count display
    wants and what a report does not.
    """
    # Make sure the rule modules have been imported
    from . import rules  # noqa: F401
    found = sorted(_REGISTRY, key=lambda r: r.id)
    if backend is None:
        return found
    return [r for r in found if backend in r.backends]


# --------------------------------------------------------------------------
# Report
# --------------------------------------------------------------------------

@dataclass
class Report:
    taken_at: str
    cluster_name: str
    version: str
    distribution: str
    #: Which configured source this is about, and what kind it is. A report
    #: with no name on it is unreadable once there is more than one backend:
    #: "retention is not set" is a different sentence for each of them.
    source: str = ""
    backend: str = "elasticsearch"
    findings: list = field(default_factory=list)
    passed: list = field(default_factory=list)    # [(rule_id, title)]
    skipped: list = field(default_factory=list)   # [(rule_id, title, reason)]
    errors: list = field(default_factory=list)    # [(rule_id, error)]
    collection_errors: dict = field(default_factory=dict)

    @property
    def counts(self):
        out = {s.value: 0 for s in Severity}
        for f in self.findings:
            out[f.severity.value] += 1
        return out

    @property
    def score(self):
        """Heuristic health score (0-100).

        Not a precise measure — it exists to track trends over time and compare
        reports. Base decisions on the findings themselves.
        """
        penalty = sum({"critical": 15, "warning": 5, "info": 1}[f.severity.value]
                      for f in self.findings)
        return max(0, 100 - penalty)

    def to_dict(self):
        return {
            "taken_at": self.taken_at,
            "cluster_name": self.cluster_name,
            "version": self.version,
            "distribution": self.distribution,
            "source": self.source,
            "backend": self.backend,
            "score": self.score,
            "counts": self.counts,
            "findings": [f.to_dict() for f in self.findings],
            "passed": [{"rule_id": r, "title": t} for r, t in self.passed],
            "skipped": [{"rule_id": r, "title": t, "reason": s} for r, t, s in self.skipped],
            "errors": [{"rule_id": r, "error": e} for r, e in self.errors],
            "collection_errors": self.collection_errors,
        }


def run_rules(snapshot):
    """Run every rule against the snapshot.

    A single failing rule does not bring the report down; the error is recorded
    and execution continues. The Advisor itself must not become an outage.
    """
    backend = getattr(snapshot, "backend", "elasticsearch")
    report = Report(
        taken_at=snapshot.taken_at,
        cluster_name=snapshot.cluster_name,
        version=snapshot.version,
        distribution=snapshot.distribution,
        # NOT falling back to cluster_name. That is a different thing, it has
        # its own field, and putting it here makes `source` mean "the WDash
        # source" for collectors and "the cluster's own name" for
        # Elasticsearch — so anything matching on it, the source picker
        # included, silently fails for exactly one backend.
        source=getattr(snapshot, "source_name", ""),
        backend=backend,
        collection_errors=dict(snapshot.errors),
    )

    # Only this backend's rules. Running the whole registry would fill a Loki
    # report with skipped Elasticsearch rules — noise that makes the six that
    # matter harder to find than no report at all.
    for r in all_rules(backend):
        applicable, reason = r.applies_to(snapshot)
        if not applicable:
            report.skipped.append((r.id, r.title, reason))
            continue
        try:
            found = list(r.check(snapshot) or [])
        except Exception as exc:
            report.errors.append((r.id, f"{type(exc).__name__}: {exc}"))
            continue
        if found:
            report.findings.extend(found)
        else:
            report.passed.append((r.id, r.title))

    report.findings.sort(key=lambda f: (-f.severity.weight, f.rule_id))
    return report
