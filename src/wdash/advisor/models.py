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


class NotEvaluated(Exception):
    """Raised by a rule that cannot see what its verdict depends on.

    A rule that simply returns has passed, and "passed" is a claim about the
    cluster. When the input is missing, unreadable or not in a form the rule
    understands, the honest outcome is neither a finding nor a pass: the
    report files the rule under `not_evaluated`, with this message as the
    reason. Raise it before yielding anything.
    """


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
    #: The collected fields the verdict depends on, by the name `errors`
    #: records a failure under. When one of them failed the rule is not run:
    #: every rule reads an empty field as "nothing wrong here", so running it
    #: turned "could not look" into "passed".
    needs: tuple = ()

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
         distributions=None, backends=("elasticsearch",), needs=()):
    """Decorator that adds a rule function to the registry.

    The decorated function takes a snapshot and yields Findings. `needs`
    names the collected fields its verdict depends on.
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
            needs=tuple(needs),
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
    #: Rules that do not apply here: another distribution or version.
    skipped: list = field(default_factory=list)   # [(rule_id, title, reason)]
    #: Rules that apply and could not look: their input was not collected,
    #: or was not in a form they can read. Kept apart from `skipped`, which
    #: says nothing about this cluster; this says the report has a hole.
    not_evaluated: list = field(default_factory=list)  # [(rule_id, title, reason)]
    errors: list = field(default_factory=list)    # [(rule_id, error)]
    collection_errors: dict = field(default_factory=dict)

    @property
    def counts(self):
        out = {s.value: 0 for s in Severity}
        for f in self.findings:
            out[f.severity.value] += 1
        return out

    @property
    def evaluated(self):
        """How many rules reached a verdict, a pass or a finding."""
        return len(self.passed) + len({f.rule_id for f in self.findings})

    @property
    def complete(self):
        """Everything was collected and every rule that applies looked.

        Only a complete report may say "all rules passed"."""
        return not (self.collection_errors or self.not_evaluated or self.errors)

    @property
    def unavailable(self):
        """Nothing was evaluated, because nothing it needed arrived.

        Not a report with no findings: a report of nothing. A rule that
        RAISED counts as well as one that could not look: a report of 31
        exceptions kept a score of 100 and passed the gate, although
        nothing in it had reached a verdict."""
        return self.evaluated == 0 and bool(self.collection_errors
                                            or self.not_evaluated
                                            or self.errors)

    @property
    def score(self):
        """Heuristic health score (0-100), or None when nothing was evaluated.

        Not a precise measure — it exists to track trends over time and compare
        reports. Base decisions on the findings themselves. None rather than
        100 for a report of nothing: 100 is the score of a cluster with no
        findings, and that is not what an unreachable cluster is.
        """
        if self.unavailable:
            return None
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
            "complete": self.complete,
            "counts": self.counts,
            "findings": [f.to_dict() for f in self.findings],
            "passed": [{"rule_id": r, "title": t} for r, t in self.passed],
            "skipped": [{"rule_id": r, "title": t, "reason": s} for r, t, s in self.skipped],
            "not_evaluated": [{"rule_id": r, "title": t, "reason": s}
                              for r, t, s in self.not_evaluated],
            "errors": [{"rule_id": r, "error": e} for r, e in self.errors],
            "collection_errors": self.collection_errors,
        }


def run_rules(snapshot):
    """Run every rule against the snapshot.

    A single failing rule does not bring the report down; the error is recorded
    and execution continues. The Advisor itself must not become an outage.

    A rule whose input was not collected is not run, and a rule that says it
    cannot see what it needs (`NotEvaluated`) is not counted as passed. Both
    land in `not_evaluated`: every rule reads an empty field as "nothing wrong
    here", and a cluster that refused every call used to score 100 with all
    31 rules passed.
    """
    backend = getattr(snapshot, "backend", "elasticsearch")
    failed = getattr(snapshot, "errors", None) or {}
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
        missing = [name for name in r.needs if name in failed]
        if missing:
            report.not_evaluated.append(
                (r.id, r.title, f"{', '.join(missing)} could not be collected"))
            continue
        try:
            found = list(r.check(snapshot) or [])
        except NotEvaluated as exc:
            report.not_evaluated.append((r.id, r.title, str(exc)))
            continue
        except Exception as exc:
            report.errors.append((r.id, f"{type(exc).__name__}: {exc}"))
            continue
        if found:
            report.findings.extend(found)
        else:
            report.passed.append((r.id, r.title))

    report.findings.sort(key=lambda f: (-f.severity.weight, f.rule_id))
    return report
