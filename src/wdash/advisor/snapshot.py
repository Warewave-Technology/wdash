"""
Cluster snapshot collection.

A snapshot is plain data: it serialises to JSON and loads back from disk.
Rules only ever see a snapshot, never a live connection. That separation is
what makes the rules testable — a snapshot taken from a real cluster is used
directly as a fixture.
"""

import concurrent.futures
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone

# WDash runs aggregations on these fields. The mapping rules check whether
# they are actually aggregatable.
AGGREGATED_FIELDS = ["level", "service", "host", "environment"]

# Fields expected to carry large free text — a .keyword sub-field is wasteful
LARGE_TEXT_FIELDS = ["message", "stack_trace", "body", "error.stack_trace", "exception"]


def _body(response):
    """Convert an Elasticsearch client response into a plain dict or list."""
    return getattr(response, "body", response)


@dataclass
class ClusterSnapshot:
    taken_at: str = ""
    info: dict = field(default_factory=dict)
    health: dict = field(default_factory=dict)
    cluster_settings: dict = field(default_factory=dict)
    nodes_info: dict = field(default_factory=dict)
    nodes_stats: dict = field(default_factory=dict)
    indices_stats: dict = field(default_factory=dict)
    cat_indices: list = field(default_factory=list)
    cat_shards: list = field(default_factory=list)
    index_settings: dict = field(default_factory=dict)
    index_mappings: dict = field(default_factory=dict)
    ilm_policies: dict = field(default_factory=dict)
    index_templates: dict = field(default_factory=dict)
    snapshot_repositories: dict = field(default_factory=dict)
    errors: dict = field(default_factory=dict)

    # ---------------- identity ----------------

    @property
    def cluster_name(self):
        return self.info.get("cluster_name") or self.health.get("cluster_name") or "unknown"

    @property
    def version(self):
        return (self.info.get("version") or {}).get("number", "unknown")

    @property
    def version_tuple(self):
        parts = []
        for chunk in self.version.split("."):
            digits = "".join(c for c in chunk if c.isdigit())
            parts.append(int(digits) if digits else 0)
        while len(parts) < 3:
            parts.append(0)
        return tuple(parts[:3])

    @property
    def distribution(self):
        """'elasticsearch' | 'opensearch' | ..."""
        version = self.info.get("version") or {}
        return (version.get("distribution") or "elasticsearch").lower()

    # ---------------- node helpers ----------------

    def nodes(self):
        """Yield (node_id, info, stats) triples."""
        for node_id, info in (self.nodes_info.get("nodes") or {}).items():
            yield node_id, info, (self.nodes_stats.get("nodes") or {}).get(node_id, {})

    def node_name(self, node_id):
        return ((self.nodes_info.get("nodes") or {}).get(node_id, {})).get("name", node_id)

    @property
    def data_node_count(self):
        n = 0
        for _, info, _ in self.nodes():
            roles = info.get("roles") or []
            if any(r == "data" or r.startswith("data_") for r in roles):
                n += 1
        return max(n, 1)

    @property
    def master_eligible_count(self):
        return sum(1 for _, info, _ in self.nodes() if "master" in (info.get("roles") or []))

    def cluster_setting(self, key, default=None):
        """Read a flat setting, preferring persistent over transient over defaults."""
        for section in ("persistent", "transient", "defaults"):
            values = self.cluster_settings.get(section) or {}
            if key in values:
                return values[key]
        return default

    # ---------------- index helpers ----------------

    def user_indices(self):
        """Indices whose settings were readable, excluding system and hidden ones."""
        return sorted(
            name for name in self.index_settings
            if not name.startswith(".") and not name.startswith("_")
        )

    def index_setting(self, index, key, default=None):
        settings = (self.index_settings.get(index) or {}).get("settings") or {}
        return settings.get(key, default)

    def index_properties(self, index):
        return ((self.index_mappings.get(index) or {}).get("mappings") or {}).get("properties") or {}

    def index_mapping_root(self, index):
        return (self.index_mappings.get(index) or {}).get("mappings") or {}

    def shards_of(self, index):
        return [s for s in self.cat_shards if s.get("index") == index]

    def index_size_bytes(self, index):
        stats = (self.indices_stats.get("indices") or {}).get(index) or {}
        return (((stats.get("primaries") or {}).get("store") or {}).get("size_in_bytes")) or 0

    # ---------------- serialisation ----------------

    def to_dict(self):
        return {
            "taken_at": self.taken_at,
            "info": self.info,
            "health": self.health,
            "cluster_settings": self.cluster_settings,
            "nodes_info": self.nodes_info,
            "nodes_stats": self.nodes_stats,
            "indices_stats": self.indices_stats,
            "cat_indices": self.cat_indices,
            "cat_shards": self.cat_shards,
            "index_settings": self.index_settings,
            "index_mappings": self.index_mappings,
            "ilm_policies": self.ilm_policies,
            "index_templates": self.index_templates,
            "snapshot_repositories": self.snapshot_repositories,
            "errors": self.errors,
        }

    @classmethod
    def from_dict(cls, data):
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})

    def save(self, path):
        with open(path, "w") as fh:
            json.dump(self.to_dict(), fh, indent=2, default=str)

    @classmethod
    def load(cls, path):
        with open(path) as fh:
            return cls.from_dict(json.load(fh))


# --------------------------------------------------------------------------
# Collection
# --------------------------------------------------------------------------

def collect(es, timeout=30):
    """Take a snapshot of a live cluster.

    Every call runs in parallel and in isolation: if one fails its field stays
    empty, the error is recorded under `errors`, and the rest continue. The
    Advisor itself must not become a point of failure.
    """
    snapshot = ClusterSnapshot(taken_at=datetime.now(timezone.utc).isoformat())

    tasks = {
        "info": lambda: _body(es.info()),
        "health": lambda: _body(es.cluster.health()),
        "cluster_settings": lambda: _body(
            es.cluster.get_settings(include_defaults=True, flat_settings=True)),
        "nodes_info": lambda: _body(es.nodes.info()),
        "nodes_stats": lambda: _body(es.nodes.stats()),
        "indices_stats": lambda: _body(es.indices.stats(index="_all")),
        "cat_indices": lambda: _body(es.cat.indices(
            format="json", bytes="b",
            h="index,health,status,pri,rep,docs.count,store.size,creation.date")),
        "cat_shards": lambda: _body(es.cat.shards(
            format="json", bytes="b",
            h="index,shard,prirep,state,store,node,unassigned.reason")),
        "index_settings": lambda: _body(es.indices.get_settings(
            index="*", flat_settings=True, expand_wildcards="open")),
        "index_mappings": lambda: _body(es.indices.get_mapping(
            index="*", expand_wildcards="open")),
        "ilm_policies": lambda: _body(es.ilm.get_lifecycle()),
        "index_templates": lambda: _body(es.indices.get_index_template()),
        "snapshot_repositories": lambda: _body(es.snapshot.get_repository()),
    }

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        futures = {pool.submit(fn): name for name, fn in tasks.items()}
        for future in concurrent.futures.as_completed(futures, timeout=timeout):
            name = futures[future]
            try:
                setattr(snapshot, name, future.result())
            except Exception as exc:
                snapshot.errors[name] = f"{type(exc).__name__}: {exc}"

    return snapshot
