"""Shard design rules — the most common failure point in log clusters."""

from ..models import Finding, NotEvaluated, Severity, rule
from ._util import GB, human_bytes

CATEGORY = "shards"

#: What a rule says when it has shards or indices to judge and no data node
#: count to judge them against. Guessing one node told a three-node cluster
#: its replicas could never be allocated.
NO_DATA_NODES = "_nodes/info listed no data nodes, so there is no node count to judge by"

# Elastic's own guidance: at most ~20 shards per GB of heap per node
SHARDS_PER_GB_HEAP = 20
# Healthy shard size range for log data
MAX_HEALTHY_SHARD = 50 * GB
MIN_USEFUL_SHARD = 1 * GB


def _avg_heap_gb(snap):
    sizes = []
    for _, _, stats in snap.nodes():
        heap = ((stats.get("jvm") or {}).get("mem") or {}).get("heap_max_in_bytes")
        if heap:
            sizes.append(heap)
    if not sizes:
        return None
    return sum(sizes) / len(sizes) / GB


@rule(id="SHD001", category=CATEGORY, title="Shards per node",
      needs=("cat_shards", "nodes_info", "nodes_stats"))
def oversharding(snap):
    assigned = [s for s in snap.cat_shards if s.get("state") == "STARTED"]
    if not assigned:
        return

    data_nodes = snap.data_node_count
    if not data_nodes:
        raise NotEvaluated(NO_DATA_NODES)
    per_node = len(assigned) / data_nodes
    heap_gb = _avg_heap_gb(snap)
    if not heap_gb:
        return

    limit = SHARDS_PER_GB_HEAP * heap_gb
    if per_node <= limit:
        return

    yield Finding(
        rule_id="SHD001", category=CATEGORY,
        severity=Severity.CRITICAL if per_node > limit * 2 else Severity.WARNING,
        title="Too many shards per node",
        evidence=(f"{len(assigned)} assigned shards across {data_nodes} data node(s) "
                  f"= {per_node:.0f} per node; with {heap_gb:.1f}GB heap the "
                  f"suggested ceiling is {limit:.0f}"),
        impact="Every shard is a separate Lucene index: it holds metadata in heap and is "
               "visited separately on every query. Excessive shard counts consume memory "
               "and raise the coordination cost of each search.",
        remediation=("Move from daily to weekly or monthly indices, lower the shard count "
                     "per index, and merge old indices with _shrink. Data streams plus ILM "
                     "rollover manage shard size against a target automatically."),
        targets=[],
    )


@rule(id="SHD002", category=CATEGORY, title="Oversized shard", needs=("cat_shards",))
def shard_too_large(snap):
    offenders = []
    for shard in snap.cat_shards:
        if shard.get("prirep") != "p" or shard.get("state") != "STARTED":
            continue
        try:
            size = int(shard.get("store") or 0)
        except (TypeError, ValueError):
            continue
        if size > MAX_HEALTHY_SHARD:
            offenders.append((shard["index"], shard["shard"], size))

    if not offenders:
        return

    yield Finding(
        rule_id="SHD002", category=CATEGORY, severity=Severity.WARNING,
        title="Shard size exceeds the suggested ceiling",
        evidence="; ".join(f"{idx}[{num}]: {human_bytes(size)}"
                           for idx, num, size in offenders[:8])
                 + (f" (+{len(offenders) - 8} more shards)" if len(offenders) > 8 else ""),
        impact="Large shards slow recovery after a node failure, increase network traffic "
               "during rebalancing, and keep a single query thread busy for a long time.",
        remediation="Target 10-50GB per shard. Set the rollover threshold "
                    "(max_primary_shard_size) to 50GB, or raise the shard count per index.",
        targets=sorted({idx for idx, _, _ in offenders}),
    )


@rule(id="SHD003", category=CATEGORY, title="Index split into more shards than its size warrants",
      # Without the sizes every index reads as 0 bytes, and every
      # multi-shard index as over-sharded.
      needs=("index_settings", "indices_stats"))
def over_sharded_index(snap):
    offenders = []
    for index in snap.user_indices():
        try:
            shard_count = int(snap.index_setting(index, "index.number_of_shards") or 1)
        except (TypeError, ValueError):
            continue
        if shard_count <= 1:
            continue
        size = snap.index_size_bytes(index)
        avg = size / shard_count
        if avg < MIN_USEFUL_SHARD:
            offenders.append((index, shard_count, size, avg))

    if not offenders:
        return

    yield Finding(
        rule_id="SHD003", category=CATEGORY, severity=Severity.WARNING,
        title="Index has more shards than its size warrants",
        evidence="; ".join(
            f"{idx}: {n} shards, {human_bytes(size)} total "
            f"({human_bytes(avg)} per shard)"
            for idx, n, size, avg in offenders[:8]
        ) + (f" (+{len(offenders) - 8} more indices)" if len(offenders) > 8 else ""),
        impact="Small shards do not amortise their fixed cost: each holds metadata in heap "
               "and is visited separately per query. At this size, splitting buys no "
               "speed and only adds overhead.",
        remediation="number_of_shards=1 is enough at this size. Existing indices can be "
                    "reduced to a single shard with the _shrink API. Shard count can only "
                    "be changed by recreating the index, so update your index template too.",
        targets=[idx for idx, _, _, _ in offenders],
    )


@rule(id="SHD004", category=CATEGORY, title="Replica configuration",
      needs=("index_settings", "nodes_info"))
def replica_configuration(snap):
    indices = snap.user_indices()
    if not indices:
        return
    data_nodes = snap.data_node_count
    if not data_nodes:
        raise NotEvaluated(NO_DATA_NODES)
    unassignable, unprotected = [], []

    for index in indices:
        try:
            replicas = int(snap.index_setting(index, "index.number_of_replicas") or 0)
        except (TypeError, ValueError):
            continue
        if data_nodes == 1 and replicas > 0:
            unassignable.append((index, replicas))
        elif data_nodes > 1 and replicas == 0:
            unprotected.append(index)

    if unassignable:
        yield Finding(
            rule_id="SHD004", category=CATEGORY, severity=Severity.WARNING,
            title="Replicas requested on a single-node cluster",
            evidence="; ".join(f"{idx}: replicas={r}" for idx, r in unassignable),
            impact="A replica is never allocated to the same node as its primary. On a "
                   "single-node cluster these shards stay permanently unassigned and the "
                   "cluster reports yellow forever.",
            remediation='Remove the replica with PUT /<index>/_settings '
                        '{"index.number_of_replicas": 0}, or add a second data node.',
            targets=[idx for idx, _ in unassignable],
        )

    if unprotected:
        yield Finding(
            rule_id="SHD004", category=CATEGORY, severity=Severity.CRITICAL,
            title="Index without replicas on a multi-node cluster",
            evidence=f"{len(unprotected)} indices with replicas=0: "
                     + ", ".join(unprotected[:8])
                     + (f" (+{len(unprotected) - 8} more)" if len(unprotected) > 8 else ""),
            impact="Losing a single node destroys the data in these indices irrecoverably.",
            remediation='PUT /<index>/_settings {"index.number_of_replicas": 1}',
            targets=unprotected,
        )


@rule(id="SHD005", category=CATEGORY, title="Cluster shard limit",
      needs=("cluster_settings", "cat_shards", "nodes_info"))
def approaching_shard_limit(snap):
    try:
        per_node_limit = int(snap.cluster_setting("cluster.max_shards_per_node", 1000))
    except (TypeError, ValueError):
        per_node_limit = 1000

    open_shards = len([s for s in snap.cat_shards if s.get("state") in ("STARTED", "INITIALIZING")])
    if not open_shards:
        return
    if not snap.data_node_count:
        raise NotEvaluated(NO_DATA_NODES)
    total_limit = per_node_limit * snap.data_node_count
    if not total_limit:
        return

    usage = open_shards / total_limit * 100
    if usage < 70:
        return

    yield Finding(
        rule_id="SHD005", category=CATEGORY,
        severity=Severity.CRITICAL if usage >= 90 else Severity.WARNING,
        title="Approaching the cluster shard limit",
        evidence=f"{open_shards} of {total_limit} shards ({usage:.0f}%) "
                 f"[cluster.max_shards_per_node={per_node_limit} x "
                 f"{snap.data_node_count} data node(s)]",
        impact="Once the limit is reached no new index can be created. In a system built "
               "on time-based indices that means tomorrow's index fails to open and "
               "ingestion stops.",
        remediation="Lower the shard count rather than raising the limit: delete or _shrink "
                    "old indices and apply retention with ILM. Raising the limit only "
                    "increases heap pressure.",
        targets=[],
    )
