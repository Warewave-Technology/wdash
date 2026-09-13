#!/usr/bin/env python3
"""
WDash lab data generator.

It does two jobs at once:

1. DEVELOPMENT DATA
   Produces realistic log and trace documents. The multiple index patterns
   (app-*, service-*, infra-*) exercise RBAC, while multi-line stack traces
   and JSON messages exercise the frontend rendering paths.

2. ADVISOR FIXTURES
   Creates deliberately misconfigured indices. On a clean cluster most Advisor
   rules never fire; these indices let us verify both that the rules trigger
   correctly and that they do not raise false alarms on healthy indices.

Usage:
    python3 seed.py                      # default: 50k logs, 2k traces, 7 days
    python3 seed.py --reset              # drop existing lab indices first
    python3 seed.py --logs 200000        # larger volume
    python3 seed.py --only traces
"""

import argparse
import json
import os
import random
import sys
import uuid
from datetime import datetime, timedelta, timezone

try:
    from elasticsearch import Elasticsearch, helpers
except ImportError:
    sys.exit(
        "the elasticsearch library is missing.\n"
        "  pip install 'elasticsearch>=8,<9'\n"
        "or activate the project venv."
    )

# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------

SERVICES = [
    "api-gateway",
    "auth-service",
    "payment-service",
    "user-service",
    "notification-service",
    "search-service",
]

HOSTS = [f"node-{i}" for i in range(1, 6)]
ENVIRONMENTS = ["production", "staging"]

# Weighted level distribution, close to a real logging profile
LEVEL_WEIGHTS = [("INFO", 70), ("DEBUG", 8), ("WARN", 12), ("ERROR", 9), ("FATAL", 1)]

MESSAGES = {
    "api-gateway": [
        "GET /api/v1/orders returned {status} in {ms}ms",
        "POST /api/v1/checkout returned {status} in {ms}ms",
        "rate limit applied for client {client}",
        "upstream {svc} responded in {ms}ms",
    ],
    "auth-service": [
        "token issued for subject {client}",
        "token validation failed: signature mismatch",
        "LDAP bind completed in {ms}ms",
        "session refreshed for {client}",
    ],
    "payment-service": [
        "charge authorized amount={amount} currency=EUR",
        "charge declined amount={amount} reason=insufficient_funds",
        "stripe API call completed in {ms}ms",
        "reconciliation batch processed {n} records",
    ],
    "user-service": [
        "profile updated for user {client}",
        "user lookup by email took {ms}ms",
        "cache miss for user {client}, falling back to database",
    ],
    "notification-service": [
        "email dispatched to queue, template=order_confirmation",
        "SMS delivery failed, provider timeout after {ms}ms",
        "push notification batch of {n} sent",
    ],
    "search-service": [
        "query executed in {ms}ms, hits={n}",
        "index refresh completed in {ms}ms",
        "slow query detected, took {ms}ms",
    ],
}

STACK_TRACE = """java.sql.SQLTransientConnectionException: HikariPool-1 - Connection is not available, request timed out after 30000ms
\tat com.zaxxer.hikari.pool.HikariPool.createTimeoutException(HikariPool.java:696)
\tat com.zaxxer.hikari.pool.HikariPool.getConnection(HikariPool.java:197)
\tat com.warewave.{svc}.repository.OrderRepository.findById(OrderRepository.java:84)
\tat com.warewave.{svc}.service.OrderService.process(OrderService.java:142)
\tat com.warewave.{svc}.web.OrderController.get(OrderController.java:57)
\tat java.base/java.lang.Thread.run(Thread.java:840)"""

# Trace topology: caller -> callees
TOPOLOGY = {
    "api-gateway": ["auth-service", "payment-service", "user-service", "search-service"],
    "auth-service": ["redis", "postgres"],
    "payment-service": ["postgres", "stripe-api"],
    "user-service": ["postgres", "redis"],
    "search-service": ["elasticsearch"],
    "notification-service": ["postgres"],
}
LEAF_KINDS = {
    "postgres": ("db", "postgresql"),
    "redis": ("db", "redis"),
    "elasticsearch": ("db", "elasticsearch"),
    "stripe-api": ("external", "http"),
}

# --------------------------------------------------------------------------
# Index definitions
# --------------------------------------------------------------------------

# A correctly configured log mapping. The Advisor should pass these cleanly.
GOOD_LOG_MAPPING = {
    "properties": {
        "@timestamp": {"type": "date"},
        # keyword, so terms aggregations work — the code aggregates on level.
        "level": {"type": "keyword"},
        "service": {"type": "keyword"},
        "host": {"type": "keyword"},
        "environment": {"type": "keyword"},
        # message is text only, with NO keyword sub-field. Indexing a field
        # that is never aggregated a second time just wastes storage.
        "message": {"type": "text"},
        "request_id": {"type": "keyword"},
        "correlation_id": {"type": "keyword"},
        "trace_id": {"type": "keyword"},
        "duration_ms": {"type": "integer"},
        "http_status": {"type": "short"},
        "user_id": {"type": "keyword"},
    }
}

GOOD_LOG_SETTINGS = {
    "number_of_shards": 1,
    "number_of_replicas": 0,  # single-node lab; a replica would pin it yellow
    "refresh_interval": "30s",  # the right value for a write-heavy log index
    # Our most frequent query is "@timestamp desc"; index sorting enables
    # early termination.
    "sort.field": "@timestamp",
    "sort.order": "desc",
}

# Deliberately broken. Every setting maps to an Advisor rule.
BAD_LOG_MAPPING = {
    # dynamic:true with no template -> mapping explosion
    "dynamic": True,
    "properties": {
        "@timestamp": {"type": "date"},
        # level is indexed as TEXT. A {"terms": {"field": "level"}} aggregation
        # fails on this index.
        "level": {"type": "text"},
        # message as both text and keyword -> redundant double storage
        "message": {
            "type": "text",
            "fields": {"keyword": {"type": "keyword", "ignore_above": 256}},
        },
        "service": {"type": "text"},
        "host": {"type": "text"},
    },
}

BAD_LOG_SETTINGS = {
    # Five shards on a single node -> oversharding
    "number_of_shards": 5,
    # replica=1 on a single node -> unassignable shard -> yellow cluster
    "number_of_replicas": 1,
    "refresh_interval": "1s",  # the default; wrong for a write-heavy index
}

OTEL_TRACE_MAPPING = {
    "properties": {
        "@timestamp": {"type": "date"},
        "trace_id": {"type": "keyword"},
        "span_id": {"type": "keyword"},
        "parent_span_id": {"type": "keyword"},
        "name": {"type": "keyword"},
        "kind": {"type": "keyword"},
        # These names are the ones the OpenTelemetry Collector's Elasticsearch
        # exporter actually writes in `mapping.mode: otel`. An earlier version
        # of this file invented `duration_ns`, `status_code` and a flat
        # `resource` — and the reader was written to match, so fixture and
        # reader agreed with each other and with nothing real. Running a
        # collector in the lab is what caught it; keep this shape honest.
        "duration": {"type": "long"},
        "status": {
            "properties": {"code": {"type": "keyword"}}
        },
        "resource": {
            "properties": {
                "attributes": {
                    "properties": {
                        "service.name": {"type": "keyword"},
                        "service.version": {"type": "keyword"},
                        "deployment.environment": {"type": "keyword"},
                        "host.name": {"type": "keyword"},
                    }
                }
            }
        },
        "attributes": {
            "properties": {
                "http.request.method": {"type": "keyword"},
                "http.response.status_code": {"type": "short"},
                "url.path": {"type": "keyword"},
                "db.system": {"type": "keyword"},
                "db.statement": {"type": "text"},
                "server.address": {"type": "keyword"},
                "error.type": {"type": "keyword"},
            }
        },
    }
}

APM_TRACE_MAPPING = {
    "properties": {
        "@timestamp": {"type": "date"},
        "trace": {"properties": {"id": {"type": "keyword"}}},
        "transaction": {
            "properties": {
                "id": {"type": "keyword"},
                "name": {"type": "keyword"},
                "type": {"type": "keyword"},
                "duration": {"properties": {"us": {"type": "long"}}},
            }
        },
        "span": {
            "properties": {
                "id": {"type": "keyword"},
                "name": {"type": "keyword"},
                "type": {"type": "keyword"},
                "subtype": {"type": "keyword"},
                "duration": {"properties": {"us": {"type": "long"}}},
            }
        },
        "parent": {"properties": {"id": {"type": "keyword"}}},
        "service": {
            "properties": {
                "name": {"type": "keyword"},
                "version": {"type": "keyword"},
                "environment": {"type": "keyword"},
            }
        },
        "event": {"properties": {"outcome": {"type": "keyword"}}},
        "processor": {"properties": {"event": {"type": "keyword"}}},
    }
}

TRACE_SETTINGS = {
    "number_of_shards": 1,
    "number_of_replicas": 0,
    "refresh_interval": "30s",
}

# (index, settings, mappings)
INDICES = [
    ("app-logs-000001", GOOD_LOG_SETTINGS, GOOD_LOG_MAPPING),
    ("service-logs-000001", GOOD_LOG_SETTINGS, GOOD_LOG_MAPPING),
    ("infra-logs-000001", GOOD_LOG_SETTINGS, GOOD_LOG_MAPPING),
    ("bad-logs-000001", BAD_LOG_SETTINGS, BAD_LOG_MAPPING),
    ("otel-traces-000001", TRACE_SETTINGS, OTEL_TRACE_MAPPING),
    # Deliberately NOT "traces-apm-*": Elasticsearch's built-in
    # "traces-apm@template" owns that pattern and only permits data streams.
    # What matters for testing the adapter is the document schema, not the
    # index type.
    ("apm-traces-000001", TRACE_SETTINGS, APM_TRACE_MAPPING),
]

LOG_INDICES = ["app-logs-000001", "service-logs-000001", "infra-logs-000001"]

# Random field pool for bad-logs: ~600 fields, about 60% of the default
# 1000-field limit, which trips the "approaching the field limit" rule.
JUNK_FIELDS = [f"attr_{i}" for i in range(600)]


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def weighted_choice(pairs):
    total = sum(w for _, w in pairs)
    r = random.uniform(0, total)
    upto = 0
    for value, weight in pairs:
        upto += weight
        if upto >= r:
            return value
    return pairs[-1][0]


def random_timestamp(days, now):
    """A timestamp spread over the last `days`, weighted towards recent time."""
    # squared weighting: recent hours are denser
    frac = random.random() ** 2
    delta = timedelta(days=days) * frac
    return now - delta


def iso(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


# --------------------------------------------------------------------------
# Log generation
# --------------------------------------------------------------------------

def make_log(ts, index, trace_pool=None):
    service = random.choice(SERVICES)
    level = weighted_choice(LEVEL_WEIGHTS)
    template = random.choice(MESSAGES[service])

    message = template.format(
        status=random.choice([200, 200, 200, 201, 400, 404, 500, 503]),
        ms=random.randint(2, 4200),
        client=f"user-{random.randint(1000, 9999)}",
        amount=f"{random.uniform(5, 900):.2f}",
        n=random.randint(1, 5000),
        svc=random.choice(SERVICES),
    )

    # Some errors carry a multi-line stack trace, exercising the frontend's
    # multi-line rendering path
    if level in ("ERROR", "FATAL") and random.random() < 0.35:
        message = message + "\n" + STACK_TRACE.format(svc=service.replace("-service", ""))

    # A small share of JSON messages, exercising syntax highlighting
    elif random.random() < 0.04:
        message = json.dumps(
            {
                "event": "request_completed",
                "route": random.choice(["/api/v1/orders", "/api/v1/users", "/healthz"]),
                "duration_ms": random.randint(1, 900),
                "cached": random.choice([True, False]),
                "upstream": random.choice(SERVICES),
            },
            indent=2,
        )

    doc = {
        "@timestamp": iso(ts),
        "level": level,
        "service": service,
        "host": random.choice(HOSTS),
        "environment": random.choice(ENVIRONMENTS),
        "message": message,
        "request_id": str(uuid.uuid4()),
        "correlation_id": f"corr-{random.randint(10000, 99999)}",
        "duration_ms": random.randint(1, 5000),
        "http_status": random.choice([200, 200, 200, 201, 400, 404, 500, 503]),
        "user_id": f"user-{random.randint(1000, 9999)}",
    }

    # Correlation is applied by the caller, which also moves the timestamp to
    # match the trace. Doing it here would produce logs that carry a trace id
    # but sit days away from the trace in time — correlated on paper only.

    # bad-logs: inflate the mapping by adding random fields to each document
    if index == "bad-logs-000001":
        for name in random.sample(JUNK_FIELDS, random.randint(3, 10)):
            # Pick a CONSISTENT type per field. Dynamic mapping locks a field to
            # the first type it sees; sending a different type later raises
            # document_parsing_exception. The goal is to inflate the mapping,
            # not to break indexing.
            bucket = int(name.rsplit("_", 1)[1]) % 3
            if bucket == 0:
                doc[name] = random.randint(1, 1000)
            elif bucket == 1:
                doc[name] = f"value-{random.randint(1, 100)}"
            else:
                doc[name] = round(random.random() * 100, 3)

    return doc


def generate_logs(count, days, now, trace_seeds=None):
    """Yield documents as (index, doc) pairs.

    `trace_seeds` is a list of (trace_id, start_time). A share of the logs is
    attached to one of them AND moved next to it in time: a real service emits
    its log lines while it is handling the request, so a correlated log that
    sits days away from its trace would be a fixture that only looks correct.
    """
    trace_seeds = trace_seeds or []

    for _ in range(count):
        # 8% go to the broken index — enough for the fixture, not much volume
        index = "bad-logs-000001" if random.random() < 0.08 else random.choice(LOG_INDICES)

        if trace_seeds and random.random() < 0.3:
            trace_id, trace_start = random.choice(trace_seeds)
            # Within the request's own lifetime, give or take a moment.
            ts = trace_start + timedelta(milliseconds=random.uniform(-200, 3000))
            doc = make_log(ts, index)
            doc["trace_id"] = trace_id
        else:
            doc = make_log(random_timestamp(days, now), index)

        yield index, doc

    # Guarantee the default "last hour" view is not empty
    for _ in range(max(200, count // 100)):
        index = random.choice(LOG_INDICES)
        ts = now - timedelta(minutes=random.uniform(0, 14))
        yield index, make_log(ts, index)


# --------------------------------------------------------------------------
# Trace generation
# --------------------------------------------------------------------------

def build_spans(trace_id, service, start, budget_us, parent_id, depth, out):
    """Generate nested spans by walking the topology.

    The budget is distributed so a parent's duration exceeds the sum of its
    children.
    """
    span_id = uuid.uuid4().hex[:16]
    children = TOPOLOGY.get(service, [])

    # Leaf calls (db/external), or the depth limit
    if depth >= 2 or not children:
        duration = max(200, int(budget_us * random.uniform(0.3, 0.8)))
        out.append((service, span_id, parent_id, start, duration, True))
        return span_id, duration

    picked = random.sample(children, random.randint(1, min(len(children), 3)))
    own_overhead = int(budget_us * random.uniform(0.05, 0.15))
    child_budget = (budget_us - own_overhead) / max(len(picked), 1)

    cursor = start + timedelta(microseconds=own_overhead // 2)
    consumed = own_overhead
    for child in picked:
        _, child_dur = build_spans(
            trace_id, child, cursor, child_budget, span_id, depth + 1, out
        )
        cursor += timedelta(microseconds=child_dur)
        consumed += child_dur

    out.append((service, span_id, parent_id, start, consumed, False))
    return span_id, consumed


def generate_traces(trace_seeds, days, now):
    for trace_id, start in trace_seeds:

        # Latency distribution: mostly fast with a long tail, so p99 is visible
        if random.random() < 0.02:
            budget = random.randint(2_000_000, 9_000_000)   # 2-9 s
        elif random.random() < 0.15:
            budget = random.randint(300_000, 2_000_000)     # 300ms-2s
        else:
            budget = random.randint(8_000, 300_000)         # 8-300ms

        spans = []
        build_spans(trace_id, "api-gateway", start, budget, None, 0, spans)

        failed = random.random() < 0.07
        env = random.choice(ENVIRONMENTS)
        host = random.choice(HOSTS)

        for service, span_id, parent_id, sstart, duration, is_leaf in spans:
            is_root = parent_id is None
            outcome = "failure" if (failed and is_root) else "success"
            status = "ERROR" if outcome == "failure" else "OK"

            db_system, subtype = LEAF_KINDS.get(service, (None, None))

            # Both schemas must describe the SAME logical span, otherwise the
            # lab is an invalid fixture for verifying schema independence.
            #   non-leaf = an inbound request handled by a service
            #              -> OTel SERVER / APM transaction
            #   leaf     = an outbound call to infrastructure
            #              -> OTel CLIENT / APM span
            op_name = (f"{service} query" if is_leaf
                       else f"GET /api/v1/{service.replace('-service', '')}")

            # --- OpenTelemetry semantic conventions ---
            otel = {
                "@timestamp": iso(sstart),
                "trace_id": trace_id,
                "span_id": span_id,
                "parent_span_id": parent_id,
                "name": op_name,
                "kind": "Client" if is_leaf else "Server",
                "duration": duration * 1000,
                "status": {"code": "Ok" if status == "OK" else "Error"},
                "resource": {
                    "attributes": {
                        "service.name": service,
                        "service.version": "1.4.2",
                        "deployment.environment": env,
                        "host.name": host,
                    }
                },
                "attributes": {},
            }
            if db_system:
                otel["attributes"]["db.system"] = db_system
                otel["attributes"]["db.statement"] = "SELECT * FROM orders WHERE id = ?"
                otel["attributes"]["server.address"] = f"{service}.internal"
            else:
                otel["attributes"]["http.request.method"] = "GET"
                otel["attributes"]["http.response.status_code"] = 500 if outcome == "failure" else 200
                otel["attributes"]["url.path"] = f"/api/v1/{service.replace('-service', '')}"
            if outcome == "failure":
                otel["attributes"]["error.type"] = "UpstreamTimeout"

            yield "otel-traces-000001", otel

            # --- Elastic APM / ECS shape (used to test the adapter layer) ---
            apm = {
                "@timestamp": iso(sstart),
                "trace": {"id": trace_id},
                "service": {"name": service, "version": "1.4.2", "environment": env},
                "event": {"outcome": outcome},
                "parent": {"id": parent_id} if parent_id else {},
            }
            if not is_leaf:
                apm["processor"] = {"event": "transaction"}
                apm["transaction"] = {
                    "id": span_id,
                    "name": op_name,
                    "type": "request",
                    "duration": {"us": duration},
                }
            else:
                apm["processor"] = {"event": "span"}
                apm["span"] = {
                    "id": span_id,
                    "name": op_name,
                    "type": db_system or "app",
                    "subtype": subtype or "internal",
                    "duration": {"us": duration},
                }

            yield "apm-traces-000001", apm


# --------------------------------------------------------------------------
# Index management
# --------------------------------------------------------------------------

def recreate_indices(es, reset):
    names = [name for name, _, _ in INDICES]

    if reset:
        print(f"  dropping existing lab indices: {', '.join(names)}")
        es.indices.delete(index=",".join(names), ignore_unavailable=True)

    for name, settings, mappings in INDICES:
        if es.indices.exists(index=name):
            print(f"  {name:26s} already exists, skipping")
            continue
        try:
            es.indices.create(index=name, settings=settings, mappings=mappings)
        except Exception as exc:
            print(f"  {name:26s} COULD NOT BE CREATED: {exc}")
            print("    (an index template may own this pattern:"
                  f" GET _index_template/_simulate_index/{name})")
            continue
        flag = "  <- Advisor fixture (deliberately broken)" if name.startswith("bad-") else ""
        print(f"  {name:26s} created{flag}")


def bulk_load(es, pairs, label):
    actions = ({"_index": index, "_source": doc} for index, doc in pairs)
    ok, errors = helpers.bulk(
        es.options(request_timeout=180),
        actions,
        chunk_size=2000,
        raise_on_error=False,
    )
    print(f"  {label}: {ok} documents written", end="")
    if errors:
        print(f", {len(errors)} errors (first: {str(errors[0])[:160]})")
    else:
        print()
    return ok


# --------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="WDash lab data generator")
    # The lab's own name for its cluster, shared with tests/test_hub.py and
    # CI. The application reads no cluster address from the environment.
    parser.add_argument("--url", default=os.environ.get("WDASH_LAB_URL") or "http://localhost:9200")
    parser.add_argument("--logs", type=int, default=50_000, help="number of log documents")
    parser.add_argument("--traces", type=int, default=2_000, help="number of traces")
    parser.add_argument("--days", type=int, default=7, help="number of days to spread the data over")
    parser.add_argument("--reset", action="store_true", help="drop existing lab indices first")
    parser.add_argument("--only", choices=["logs", "traces"], help="generate only this signal")
    parser.add_argument("--seed", type=int, default=None, help="RNG seed, for reproducible data")
    args = parser.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    kwargs = {"hosts": [args.url], "verify_certs": False, "request_timeout": 60}
    user = os.environ.get("ELASTICSEARCH_USERNAME")
    password = os.environ.get("ELASTICSEARCH_PASSWORD")
    if user and password:
        kwargs["basic_auth"] = (user, password)

    es = Elasticsearch(**kwargs)

    try:
        info = es.info()
    except Exception as exc:
        sys.exit(f"could not connect to Elasticsearch at {args.url}: {exc}")

    print(f"Connected: {info['version']['number']} at {args.url} (cluster: {info['cluster_name']})\n")

    print("Preparing indices")
    recreate_indices(es, args.reset)

    now = datetime.now(timezone.utc)
    total = 0

    # Trace ids AND their start times are decided up front, so correlated logs
    # can be placed next to their trace in time as well as by id.
    trace_seeds = [(uuid.uuid4().hex, random_timestamp(args.days, now))
                   for _ in range(args.traces)]

    if args.only != "traces":
        print(f"\nGenerating logs ({args.logs:,} documents over {args.days} days)")
        total += bulk_load(es, generate_logs(args.logs, args.days, now, trace_seeds),
                           "logs")

    if args.only != "logs":
        print(f"\nGenerating traces ({args.traces:,} traces, two schemas)")
        total += bulk_load(es, generate_traces(trace_seeds, args.days, now), "spans")

    print("\nRefreshing indices")
    es.indices.refresh(index=",".join(name for name, _, _ in INDICES))

    print("\nSummary")
    stats = es.indices.stats(index=",".join(name for name, _, _ in INDICES))
    for name in sorted(stats["indices"]):
        docs = stats["indices"][name]["primaries"]["docs"]["count"]
        size = stats["indices"][name]["primaries"]["store"]["size_in_bytes"] / 1024 / 1024
        print(f"  {name:26s} {docs:>9,} docs   {size:>7.1f} MB")

    health = es.cluster.health()
    print(f"\nCluster status: {health['status']} "
          f"({health['active_shards']} active, {health['unassigned_shards']} unassigned shards)")
    if health["status"] == "yellow":
        print("  Note: bad-logs-000001 asks for replica=1 on a single node. This is"
              "\n  expected, and a finding the Advisor should report.")

    print(f"\nWrote {total:,} documents in total.")


if __name__ == "__main__":
    main()
