"""Cluster and node level rules."""

from ..models import Finding, Severity, rule
from ._util import GB, human_bytes, parse_percent

CATEGORY = "cluster"


@rule(id="CLU001", category=CATEGORY, title="Cluster status")
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


@rule(id="CLU002", category=CATEGORY, title="JVM heap usage")
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


@rule(id="CLU003", category=CATEGORY, title="Heap above the compressed oops threshold")
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


@rule(id="CLU004", category=CATEGORY, title="Heap to system memory ratio")
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


@rule(id="CLU005", category=CATEGORY, title="Memory locking (mlockall)")
def memory_lock(snap):
    unlocked = [snap.node_name(nid) for nid, info, _ in snap.nodes()
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


@rule(id="CLU006", category=CATEGORY, title="Disk watermarks")
def disk_watermarks(snap):
    low = parse_percent(snap.cluster_setting("cluster.routing.allocation.disk.watermark.low"))
    high = parse_percent(snap.cluster_setting("cluster.routing.allocation.disk.watermark.high"))
    flood = parse_percent(snap.cluster_setting(
        "cluster.routing.allocation.disk.watermark.flood_stage"))

    # Watermarks can be expressed in bytes (for example '100gb'), which cannot be
    # compared against a percentage. Fall back to the defaults rather than skipping.
    low, high, flood = low or 85.0, high or 90.0, flood or 95.0

    for node_id, _, stats in snap.nodes():
        fs_total = (stats.get("fs") or {}).get("total") or {}
        total = fs_total.get("total_in_bytes")
        available = fs_total.get("available_in_bytes")
        if not total or available is None:
            continue

        used_pct = (1 - available / total) * 100
        name = snap.node_name(node_id)
        evidence = (f"{name}: {used_pct:.1f}% used "
                    f"({human_bytes(total - available)} of {human_bytes(total)})")

        if used_pct >= flood:
            yield Finding(
                rule_id="CLU006", category=CATEGORY, severity=Severity.CRITICAL,
                title="Disk is past the flood-stage watermark",
                evidence=f"{evidence}, flood stage at {flood:.0f}%",
                impact="Elasticsearch applies a read-only-allow-delete block to every "
                       "index on this node. Writes STOP.",
                remediation="Free space urgently, then clear the block: "
                            'PUT /_all/_settings {"index.blocks.read_only_allow_delete": null}',
                targets=[name],
            )
        elif used_pct >= high:
            yield Finding(
                rule_id="CLU006", category=CATEGORY, severity=Severity.CRITICAL,
                title="Disk is past the high watermark",
                evidence=f"{evidence}, high watermark at {high:.0f}%",
                impact="Elasticsearch will try to relocate shards away from this node. "
                       "If space is not freed it reaches flood stage and writes stop.",
                remediation="Delete or archive old indices, apply an ILM policy, or add "
                            "disk capacity.",
                targets=[name],
            )
        elif used_pct >= low:
            yield Finding(
                rule_id="CLU006", category=CATEGORY, severity=Severity.WARNING,
                title="Disk is past the low watermark",
                evidence=f"{evidence}, low watermark at {low:.0f}%",
                impact="Elasticsearch stops allocating new shards to this node. Creating "
                       "a new index may leave shards unassigned.",
                remediation="Apply a retention policy (ILM) or add capacity.",
                targets=[name],
            )


@rule(id="CLU007", category=CATEGORY, title="Thread pool rejections")
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


@rule(id="CLU008", category=CATEGORY, title="Circuit breaker trips")
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


@rule(id="CLU009", category=CATEGORY, title="Master-eligible node count")
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
