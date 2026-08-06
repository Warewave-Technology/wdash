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

    def get(self, name):
        return self.buckets.get(name, [])

    def to_dict(self):
        return {"total": self.total,
                "buckets": {k: [b.to_dict() for b in v] for k, v in self.buckets.items()},
                "warnings": list(self.warnings),
                "failed": self.failed}
