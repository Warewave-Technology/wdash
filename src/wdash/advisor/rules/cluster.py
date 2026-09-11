"""Cluster and node level rules."""

import math

from ..models import Finding, NotEvaluated, Severity, rule
from ._util import GB, human_bytes, parse_bytes, parse_watermark

CATEGORY = "cluster"

#: Per-node statistics come from two calls: which nodes, and their numbers.
NODES = ("nodes_info", "nodes_stats")


@rule(id="CLU001", category=CATEGORY, title="Cluster status", needs=("health",))
def cluster_status(snap):
    status = (snap.health or {}).get("status")
    if status not in ("red", "yellow"):
        return

    unassigned = snap.health.get("unassigned_shards", 0)
    affected = sorted({s["index"] for s in snap.cat_shards if s.get("state") == "UNASSIGNED"})
    reasons = sorted({s.get("unassigned.reason") for s in snap.cat_shards
                      if s.get("state") == "UNASSIGNED" and s.get("unassigned.reason")})

    if status == "red":
        impact = ("Red means at least one PRIMARY shard is unreachable. The affected "
                  "indices will lose data or fail reads.")
        severity = Severity.CRITICAL
    else:
        impact = ("Yellow means replica shards cannot be allocated. No data is lost yet, "
                  "but there is no redundancy: losing a node loses data.")
        severity = Severity.WARNING

    yield Finding(
        rule_id="CLU001", category=CATEGORY, severity=severity,
        title=f"Cluster status is {status}",
        evidence=(f"status={status}, unassigned shards={unassigned}, "
                  f"{snap.health.get('active_shards_percent_as_number', 0):.0f}% active"
                  + (f", reason: {', '.join(reasons)}" if reasons else "")),
        impact=impact,
        remediation="Run GET _cluster/allocation/explain to see why allocation fails. "
                    "On a single-node cluster the usual cause is a replica count above "
                    "zero; set number_of_replicas to 0 on those indices.",
        targets=affected,
    )


@rule(id="CLU002", category=CATEGORY, title="JVM heap usage", needs=NODES)
def heap_usage(snap):
    hot = []
    for node_id, _, stats in snap.nodes():
        used = ((stats.get("jvm") or {}).get("mem") or {}).get("heap_used_percent")
        if used is None:
            continue
        if used >= 75:
            hot.append((snap.node_name(node_id), used))

    if not hot:
        return

    worst = max(h[1] for h in hot)
    yield Finding(
        rule_id="CLU002", category=CATEGORY,
        severity=Severity.CRITICAL if worst >= 85 else Severity.WARNING,
        title="JVM heap usage is high",
        evidence="; ".join(f"{name}: {pct}%" for name, pct in hot)
                 + " (point-in-time reading; includes garbage not yet collected)",
        impact="Sustained high heap causes continuous garbage collection. Query latency "
               "rises and circuit breakers start rejecting requests.",
        remediation="Find what is consuming heap before adding more: fielddata, large "
                    "aggregations, or excessive shard counts. Check GET _nodes/stats/breaker "
                    "and GET _cat/fielddata. Growing the heap usually postpones the symptom "
                    "rather than fixing the cause.",
        targets=[name for name, _ in hot],
    )


@rule(id="CLU003", category=CATEGORY, title="Heap above the compressed oops threshold",
      needs=NODES)
def heap_over_compressed_oops(snap):
    offenders = []
    for node_id, _, stats in snap.nodes():
        heap_max = ((stats.get("jvm") or {}).get("mem") or {}).get("heap_max_in_bytes")
        if heap_max and heap_max > 32 * GB:
            offenders.append((snap.node_name(node_id), heap_max))

    if not offenders:
        return

    yield Finding(
        rule_id="CLU003", category=CATEGORY, severity=Severity.WARNING,
        title="Heap exceeds 32GB",
        evidence="; ".join(f"{name}: {human_bytes(size)}" for name, size in offenders),
        impact="Above 32GB the JVM turns off compressed ordinary object pointers. "
               "Pointers become 8 bytes and effective capacity DROPS — you end up "
               "storing fewer objects with more heap.",
        remediation="Reduce the heap to 31GB. If the machine has more memory, leave it "
                    "to the operating system's file cache, which Lucene relies on. Add "
                    "nodes for more capacity.",
        targets=[name for name, _ in offenders],
    )


@rule(id="CLU004", category=CATEGORY, title="Heap to system memory ratio", needs=NODES)
def heap_ratio(snap):
    for node_id, _, stats in snap.nodes():
        jvm_mem = (stats.get("jvm") or {}).get("mem") or {}
        os_mem = (stats.get("os") or {}).get("mem") or {}
        heap_max = jvm_mem.get("heap_max_in_bytes")
        total = os_mem.get("total_in_bytes")
        if not heap_max or not total:
            continue

        ratio = heap_max / total * 100
        name = snap.node_name(node_id)

        if ratio > 60:
            yield Finding(
                rule_id="CLU004", category=CATEGORY, severity=Severity.WARNING,
                title="Heap is large relative to system memory",
                evidence=f"{name}: heap {human_bytes(heap_max)} of "
                         f"{human_bytes(total)} RAM ({ratio:.0f}%)",
                impact="Lucene reads segments through the operating system's file cache. "
                       "If the heap takes more than half of RAM there is little left for "
                       "that cache, and disk reads increase — queries get slower as the "
                       "heap grows.",
                remediation="Set the heap to roughly 50% of total RAM, never above 31GB.",
                targets=[name],
            )
        elif ratio < 25:
            yield Finding(
                rule_id="CLU004", category=CATEGORY, severity=Severity.INFO,
                title="Heap is small relative to system memory",
                evidence=f"{name}: heap {human_bytes(heap_max)} of "
                         f"{human_bytes(total)} RAM ({ratio:.0f}%)",
                impact="There may be unused memory. In containers this reading can be "
                       "misleading: os.mem sometimes reports host RAM rather than the "
                       "container limit.",
                remediation="In a container, confirm the real memory limit first. If the "
                            "memory is genuinely free, raise the heap to about 50% of RAM.",
                targets=[name],
            )


@rule(id="CLU005", category=CATEGORY, title="Memory locking (mlockall)",
      needs=("nodes_info",))
def memory_lock(snap):
    unlocked = [snap.node_name(nid) for nid, info in snap.node_infos()
                if (info.get("process") or {}).get("mlockall") is False]
    if not unlocked:
        return

    yield Finding(
        rule_id="CLU005", category=CATEGORY, severity=Severity.WARNING,
        title="Heap is not locked into memory",
        evidence=f"mlockall=false: {', '.join(unlocked)}",
        impact="The operating system may swap the JVM heap to disk. A swapped heap turns "
               "garbage collection pauses into seconds and can drop the node out of the "
               "cluster.",
        remediation="Set bootstrap.memory_lock: true and give the container an unlimited "
                    "memlock ulimit. Alternatively disable swap system-wide.",
        targets=unlocked,
    )


WATERMARK = "cluster.routing.allocation.disk.watermark."

#: Elasticsearch's own defaults: each watermark, and the most free space it
#: asks for (max_headroom, 8.5 and later) while the watermark is that default.
DISK_DEFAULTS = {"flood_stage": ("95%", 100 * GB), "high": ("90%", 150 * GB),
                 "low": ("85%", 200 * GB)}

#: What each stage does, the worst first: a disk past flood stage is past the
#: other two as well, and only the worst is worth saying.
DISK_STAGES = (
    ("flood_stage", Severity.CRITICAL, "Disk is past the flood-stage watermark",
     "flood stage",
     "Elasticsearch applies a read-only-allow-delete block to every index on "
     "this node. Writes STOP.",
     "Free space urgently, then clear the block: "
     'PUT /_all/_settings {"index.blocks.read_only_allow_delete": null}'),
    ("high", Severity.CRITICAL, "Disk is past the high watermark", "high watermark",
     "Elasticsearch will try to relocate shards away from this node. If space is "
     "not freed it reaches flood stage and writes stop.",
     "Delete or archive old indices, apply an ILM policy, or add disk capacity."),
    ("low", Severity.WARNING, "Disk is past the low watermark", "low watermark",
     "Elasticsearch stops allocating new shards to this node. Creating a new "
     "index may leave shards unassigned.",
     "Apply a retention policy (ILM) or add capacity."),
)


def _chosen(snap, key, differs_from_default):
    """Was this setting chosen rather than inherited?

    Set through the API it is in `persistent` or `transient`. Set in
    elasticsearch.yml it arrives in `defaults`, like a default, and the only
    sign is that it is not Elasticsearch's own value.
    """
    for section in ("persistent", "transient"):
        if key in (snap.cluster_settings.get(section) or {}):
            return True
    return differs_from_default


def _watermark(snap, stage):
    """(written value, parsed watermark, max_headroom in bytes or None).

    Raises NotEvaluated when either cannot be read: a default put in the
    place of a value nobody could read judged '0.97' at 95% and '10gb' at
    90%, and called both critical.
    """
    key = WATERMARK + stage
    default_mark, default_headroom = DISK_DEFAULTS[stage]
    raw = snap.cluster_setting(key)
    mark = parse_watermark(raw)
    if mark is None:
        if raw is None:
            raise NotEvaluated(f"{key} is not in the cluster settings")
        raise NotEvaluated(f"{key} = {raw!r} is not a percentage, a ratio or a "
                           f"byte size")
    if mark[0] != "ratio":
        return raw, mark, None

    # A percentage asks for at most max_headroom of free space. Its default
    # applies only while the watermark is a default too — a watermark somebody
    # set turns it off — and a headroom somebody set applies either way.
    # Before 8.5 the setting does not exist, and nothing is capped.
    headroom_key = key + ".max_headroom"
    raw_headroom = snap.cluster_setting(headroom_key)
    if raw_headroom is None:
        return raw, mark, None
    headroom_chosen = _chosen(snap, headroom_key,
                              parse_bytes(raw_headroom) != default_headroom)
    mark_chosen = _chosen(snap, key, mark != parse_watermark(default_mark))
    if mark_chosen and not headroom_chosen:
        return raw, mark, None
    if str(raw_headroom).strip() == "-1":
        return raw, mark, None
    headroom = parse_bytes(raw_headroom)
    if headroom is None:
        raise NotEvaluated(f"{headroom_key} = {raw_headroom!r} is not a byte size")
    return raw, mark, headroom


def _required_free(total, mark, headroom):
    """The free space a watermark asks for on a disk of `total` bytes, the
    way Elasticsearch works it out."""
    kind, amount = mark
    if kind == "bytes":
        return amount
    used = math.ceil(amount * total)
    if headroom is not None:
        used = max(used, total - headroom)
    return total - used


@rule(id="CLU006", category=CATEGORY, title="Disk watermarks",
      needs=("cluster_settings",) + NODES)
def disk_watermarks(snap):
    """Is a node's free space below what a watermark asks for?

    Compared in bytes, as Elasticsearch compares them. A percentage read as
    a percentage of used space put the high watermark of a 10TB disk at 90%,
    where Elasticsearch — capping it at 150GB free — puts it at 98.5%.
    """
    disks = []
    for node_id, _, stats in snap.nodes():
        fs_total = (stats.get("fs") or {}).get("total") or {}
        total = fs_total.get("total_in_bytes")
        available = fs_total.get("available_in_bytes")
        if total and available is not None:
            disks.append((snap.node_name(node_id), total, available))
    if not disks:
        return

    marks = {stage: _watermark(snap, stage) for stage, *_ in DISK_STAGES}

    for name, total, available in disks:
        used_pct = (1 - available / total) * 100
        for stage, severity, title, label, impact, remediation in DISK_STAGES:
            raw, mark, headroom = marks[stage]
            required = _required_free(total, mark, headroom)
            if available >= required:
                continue
            how = str(raw)
            if headroom is not None and required == headroom:
                how += f", capped at {human_bytes(headroom)} by max_headroom"
            yield Finding(
                rule_id="CLU006", category=CATEGORY, severity=severity, title=title,
                evidence=(f"{name}: {used_pct:.1f}% used, {human_bytes(available)} "
                          f"free of {human_bytes(total)}; the {label} ({how}) asks "
                          f"for {human_bytes(required)} free"),
                impact=impact, remediation=remediation, targets=[name])
            break


@rule(id="CLU007", category=CATEGORY, title="Thread pool rejections", needs=NODES)
def thread_pool_rejections(snap):
    watched = {
        "search": ("Search requests are being rejected", Severity.CRITICAL),
        "write": ("Write requests are being rejected", Severity.CRITICAL),
        "get": ("Document fetches are being rejected", Severity.WARNING),
    }

    for pool_name, (title, severity) in watched.items():
        offenders = []
        for node_id, _, stats in snap.nodes():
            pool = (stats.get("thread_pool") or {}).get(pool_name) or {}
            rejected = pool.get("rejected") or 0
            if rejected > 0:
                offenders.append((snap.node_name(node_id), rejected,
                                  pool.get("queue", 0), pool.get("threads", 0)))
        if not offenders:
            continue

        yield Finding(
            rule_id="CLU007", category=CATEGORY, severity=severity,
            title=title,
            evidence="; ".join(f"{n}: {r} rejected (queue={q}, threads={t})"
                               for n, r, q, t in offenders)
                     + " — counters are cumulative since node start",
            impact=f"The '{pool_name}' pool queue filled up and Elasticsearch rejected "
                   "requests. Users see this as failing queries.",
            remediation=("Reduce load rather than enlarging the pool: batch queries with "
                         "_msearch, cache aggregation results, and query fewer shards. "
                         "Pool size is derived from CPU count; raising it by hand usually "
                         "moves the problem from the queue to the heap."),
            targets=[n for n, _, _, _ in offenders],
        )


@rule(id="CLU008", category=CATEGORY, title="Circuit breaker trips", needs=NODES)
def circuit_breakers(snap):
    tripped = {}
    for node_id, _, stats in snap.nodes():
        for breaker_name, breaker in (stats.get("breakers") or {}).items():
            count = breaker.get("tripped") or 0
            if count > 0:
                tripped.setdefault(breaker_name, []).append((snap.node_name(node_id), count))

    for breaker_name, nodes in tripped.items():
        yield Finding(
            rule_id="CLU008", category=CATEGORY, severity=Severity.WARNING,
            title=f"Circuit breaker tripped: {breaker_name}",
            evidence="; ".join(f"{n}: {c} times" for n, c in nodes)
                     + " — cumulative counter",
            impact="Elasticsearch rejected requests to protect memory. Users see this as "
                   "failed queries.",
            remediation=("A 'fielddata' breaker means aggregation on an analysed text "
                         "field — see MAP001. A 'request' breaker means a single "
                         "aggregation asked for too much memory; reduce the bucket count "
                         "or narrow the time range."),
            targets=[n for n, _ in nodes],
        )


@rule(id="CLU009", category=CATEGORY, title="Master-eligible node count",
      needs=("nodes_info",))
def master_eligible_nodes(snap):
    count = snap.master_eligible_count
    if count == 0:
        return

    if count == 1:
        yield Finding(
            rule_id="CLU009", category=CATEGORY, severity=Severity.WARNING,
            title="Only one master-eligible node",
            evidence=f"master-eligible nodes: {count}",
            impact="Losing the master makes the whole cluster unavailable. There is no "
                   "high availability.",
            remediation="Use three master-eligible nodes in production. In a development "
                        "environment this finding is expected.",
            targets=[],
        )
    elif count % 2 == 0:
        yield Finding(
            rule_id="CLU009", category=CATEGORY, severity=Severity.WARNING,
            title="Even number of master-eligible nodes",
            evidence=f"master-eligible nodes: {count}",
            impact="An even count adds nothing to quorum: you get the same fault "
                   "tolerance with one node fewer, and network partitions become riskier.",
            remediation="Use an odd number of master-eligible nodes (3 or 5).",
            targets=[],
        )
