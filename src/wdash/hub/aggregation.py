"""
Neutral aggregation model.

Dashboard panels ask for things like "the ten most frequent values of this
field" or "counts bucketed over time". Expressing those in Elasticsearch
aggregation syntax would leak Elasticsearch back into the codebase, defeating
the point of the hub.

The types defined here are backend independent; adapters do the translation.
"""

from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass(frozen=True)
class Terms:
    """The most frequent values of a field."""
    name: str
    field: str                      # neutral field name — adapters map it
    size: int = 10
    missing: Optional[str] = None   # label for documents without a value
    sub: tuple = ()                 # nested aggregations


@dataclass(frozen=True)
class DateHistogram:
    """Counts bucketed over time."""
    name: str
    interval: Optional[str] = None  # None = derive from the window
    min_count: int = 0
    sub: tuple = ()


@dataclass
class Bucket:
    key: Any
    count: int
    key_text: Optional[str] = None          # readable form for date buckets
    sub: dict = field(default_factory=dict)  # name -> [Bucket]

    def to_dict(self):
        out = {"key": self.key, "count": self.count}
        if self.key_text is not None:
            out["key_text"] = self.key_text
        if self.sub:
            out["sub"] = {k: [b.to_dict() for b in v] for k, v in self.sub.items()}
        return out


@dataclass
class AggregationResult:
    total: int = 0
    buckets: dict = field(default_factory=dict)   # name -> [Bucket]
    #: Some aggregations could not run (for example the field is not
    #: aggregatable). Carrying the reason beats returning silently empty — an
    #: empty panel and "this field is mapped wrong" are not the same thing.
    warnings: tuple = ()
    #: The query did not run at all. Distinct from a query that ran and matched
    #: nothing: `total == 0` is a real answer, `failed` means there is no answer.
    #: Conflating the two lets a backend outage render as "traffic dropped to
    #: zero" — a comparison against it would be a confident lie.
    failed: bool = False
    #: The query ran and the answer is SHORT: some shards did not reply, or
    #: one member of a fan-out did not. Distinct from `failed`, which means
    #: there is no answer at all, and from a whole answer that happens to be
    #: small.
    #:
    #: It exists because a number nobody can vouch for was being vouched
    #: for. Elasticsearch fails a search outright only when EVERY shard
    #: fails; when some do it answers 200 with what the rest found, and
    #: `_shard_failure` turned that into a warning string and nothing else —
    #: so a board painted a green "Within thresholds" badge from counts the
    #: same response described as incomplete. Measured against the lab: 200,
    #: `error_count 18,609` against a critical threshold of 20,000, a green
    #: badge, and `"5 of 9 shards failed: Fielddata is disabled"` in the
    #: warnings of that same payload.
    partial: bool = False
    #: The subset of `warnings` that belongs to ONE aggregation, filed under
    #: its name: {name: [reason, ...]}.
    #:
    #: A dashboard names every aggregation after the panel that asked for it,
    #: so this is what lets a panel draw its own reason instead of "No data in
    #: this window". Matching the text was tried and cannot work: Loki
    #: prefixes two of its reasons with the aggregation name and nothing else
    #: does, Elasticsearch's commonest one ("'x' cannot be aggregated on these
    #: indices") names only the field, so two panels over the same field are
    #: indistinguishable, and a fan-out puts the SOURCE name in front of
    #: everything ("lab-loki: panel-3: …"), which defeats a prefix test
    #: outright. A key survives all three.
    #:
    #: `warnings` still carries every reason, attributed or not: the page-level
    #: list is where a shard failure and a scope message belong, and those name
    #: no aggregation.
    notes: dict = field(default_factory=dict)
    #: Which sources `total` was added up from, and how much each gave:
    #: ({name, total, failed}, ...). Filled by the fan-out, because only it
    #: has more than one answer to attribute; a single source leaves it empty
    #: and the caller names itself. Two stored rows over one cluster count
    #: every record twice, and this is what lets a page show that as two
    #: rows of one number rather than as one number that is quietly double.
    sources: tuple = ()

    def get(self, name):
        return self.buckets.get(name, [])

    def reasons(self, name):
        """Why this aggregation has nothing to show, as a tuple of strings."""
        return tuple(str(reason) for reason in self.notes.get(name, ())
                     if reason)

    def to_dict(self):
        return {"total": self.total,
                "buckets": {k: [b.to_dict() for b in v] for k, v in self.buckets.items()},
                "warnings": list(self.warnings),
                "notes": {k: list(v) for k, v in self.notes.items()},
                "failed": self.failed,
                "sources": [dict(entry) for entry in self.sources]}
