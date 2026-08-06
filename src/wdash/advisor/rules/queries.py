"""Query and cache rules."""

from ..models import Finding, Severity, rule
from ._util import human_bytes, sum_node_stat

CATEGORY = "queries"

# Below this sample size the ratio is meaningless and would fire on a fresh cluster
MIN_SAMPLE = 50


@rule(id="QRY001", category=CATEGORY, title="Request cache hit rate")
def request_cache_hit_rate(snap):
    hits = sum_node_stat(snap, "indices", "request_cache", "hit_count")
    misses = sum_node_stat(snap, "indices", "request_cache", "miss_count")
    total = hits + misses
    if total < MIN_SAMPLE:
        return

    rate = hits / total * 100
    if rate >= 30:
        return

    yield Finding(
        rule_id="QRY001", category=CATEGORY,
        severity=Severity.CRITICAL if rate < 10 else Severity.WARNING,
        title="Shard request cache almost never hits",
        evidence=f"{hits:,} hits out of {total:,} ({rate:.1f}%) — "
                 "cumulative since node start",
        impact=(
            "The request cache stores the result of size=0 aggregation queries at the "
            "shard level — exactly the shape of dashboard queries. A hit rate near zero "
            "means Elasticsearch recomputes everything for every user viewing the same "
            "panel."),
        remediation=(
            "The usual cause is precision in the time range. The cache key is the entire "
            "query body, so if 'now' is rendered at sub-second precision every request "
            "produces a unique key and the cache never hits. Round the bounds to the "
            "minute or use Elasticsearch date math (now-1h/m). In WDash these bounds come "
            "from wdash.utils.timerange."),
        targets=[],
    )


@rule(id="QRY002", category=CATEGORY, title="Query cache hit rate")
def query_cache_hit_rate(snap):
    hits = sum_node_stat(snap, "indices", "query_cache", "hit_count")
    misses = sum_node_stat(snap, "indices", "query_cache", "miss_count")
    total = hits + misses
    if total < MIN_SAMPLE:
        return

    rate = hits / total * 100
    if rate >= 20:
        return

    yield Finding(
        rule_id="QRY002", category=CATEGORY, severity=Severity.INFO,
        title="Query cache hit rate is low",
        evidence=f"{hits:,} hits out of {total:,} ({rate:.1f}%)",
        impact=("The query cache stores the result of repeated filter clauses. A low rate "
                "means filters differ on every request."),
        remediation=("Move unchanging conditions (for example environment:production) into "
                     "filter context — clauses in query context are scored and therefore "
                     "not cached. Time range filters change by nature, so a low rate here "
                     "can be normal."),
        targets=[],
    )


@rule(id="QRY003", category=CATEGORY, title="Fielddata memory usage")
def fielddata_in_use(snap):
    offenders = []
    for node_id, _, stats in snap.nodes():
        used = (((stats.get("indices") or {}).get("fielddata") or {})
                .get("memory_size_in_bytes")) or 0
        if used > 0:
            offenders.append((snap.node_name(node_id), used))

    if not offenders:
        return

    total = sum(size for _, size in offenders)
    yield Finding(
        rule_id="QRY003", category=CATEGORY,
        severity=Severity.CRITICAL if total > 512 * 1024 * 1024 else Severity.WARNING,
        title="Fielddata is occupying heap",
        evidence="; ".join(f"{name}: {human_bytes(size)}" for name, size in offenders),
        impact=("Fielddata is loaded when an aggregation or sort runs against an analysed "
                "text field, and it pulls ALL values of that field into heap. Unlike "
                "doc_values it lives in memory rather than on disk; on a large field this "
                "can drive a node to OutOfMemory."),
        remediation=("Find the query loading fielddata (GET _cat/fielddata?v), map the "
                     "field as keyword and aggregate through .keyword instead. Read this "
                     "together with the MAP001 finding."),
        targets=[name for name, _ in offenders],
    )
