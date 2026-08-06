#!/usr/bin/env python3
"""
Sample traces for the lab's Tempo.

Written over OTLP, which is how traces reach Tempo: its distributor runs an
OTLP receiver and an application exports to it exactly as it would to any
other backend. Seeding through the front door means the adapter is tested
against what Tempo stores, not against what this script imagined.

Tempo needs a moment before a freshly written trace is searchable — the lab
config keeps `complete_block_timeout` short for exactly that reason, but a
search run immediately after this script may still come back empty.

The services here are again distinct from the other backends', so a merged
trace search visibly draws from more than one and the source badge has
something to say.

    python3 seed_tempo.py                 # 200 traces over 2 hours
    python3 seed_tempo.py --traces 1000
"""

import argparse
import json
import random
import sys
import time
import urllib.error
import urllib.request

#: The lab publishes Tempo's OTLP port here. 4317/4318 belong to the
#: standalone collector and 4319 to Jaeger; a host port binds once.
DEFAULT_URL = "http://localhost:4320"

#: A small call graph. Each entry is (service, operation, children).
#: Different service names from every other backend, so a merged trace search
#: visibly draws from more than one and the source badge has something to say.
GRAPH = (
    ("mobile-bff", "GET /feed", (
        ("profile-svc", "load profile", ()),
        ("feed-ranker", "rank", (
            ("embedding-svc", "embed", ()),
            ("cache-tier", "GET keys", ()),
        )),
        ("image-cdn", "sign urls", ()),
    )),
)

#: Fraction of traces where one span fails. Rare enough that finding one is a
#: search rather than a scroll, common enough to be findable at all.
ERROR_RATE = 0.08


def _hex(bits):
    return f"{random.getrandbits(bits):0{bits // 4}x}"


def _spans(node, trace_id, parent, start_ns, failing, out):
    """One span and its subtree. Returns the instant it ended.

    Children are laid out FIRST and the parent is sized to contain them.
    Generating each duration independently produced traces where a child
    outlived its parent — self time clamps at zero for exactly that reason,
    so nothing crashed, but the waterfall looked wrong and the lab exists to
    make the adapter legible rather than to teach somebody to distrust it.
    """
    service, operation, children = node
    span_id = _hex(64)
    fails = failing == (service, operation)

    # A little of the parent's own work before it calls anything.
    own_before = random.randint(1, 8) * 1_000_000
    cursor = start_ns + own_before

    for child in children:
        cursor = _spans(child, trace_id, span_id, cursor, failing, out)
        cursor += random.randint(0, 2) * 1_000_000      # gap between calls

    # And a little after the last one returns. The parent therefore always
    # contains its children, which is what makes self time meaningful.
    end_ns = cursor + random.randint(1, 6) * 1_000_000

    out.setdefault(service, []).append({
        "traceId": trace_id, "spanId": span_id,
        **({"parentSpanId": parent} if parent else {}),
        "name": operation,
        # 2 = SPAN_KIND_SERVER, 3 = SPAN_KIND_CLIENT. A leaf is a client call.
        "kind": 3 if not children else 2,
        "startTimeUnixNano": str(start_ns),
        "endTimeUnixNano": str(end_ns),
        "attributes": [
            {"key": "http.route", "value": {"stringValue": operation}},
            {"key": "deployment.environment", "value": {"stringValue": "lab"}},
        ],
        "status": ({"code": 2, "message": "upstream refused"} if fails
                   else {"code": 1}),
    })
    return end_ns


def _flatten(node, into):
    service, operation, children = node
    into.append((service, operation))
    for child in children:
        _flatten(child, into)
    return into


def build(count, hours, seed):
    random.seed(seed)
    now_ns = int(time.time() * 1e9)
    window_ns = int(hours * 3600 * 1e9)
    every = _flatten(GRAPH[0], [])

    for _ in range(count):
        trace_id = _hex(128)
        start = now_ns - random.randint(0, window_ns)
        failing = random.choice(every) if random.random() < ERROR_RATE else None

        by_service = {}
        _spans(GRAPH[0], trace_id, None, start, failing, by_service)
        yield [
            {"resource": {"attributes": [
                {"key": "service.name", "value": {"stringValue": service}}]},
             "scopeSpans": [{"spans": spans}]}
            for service, spans in by_service.items()
        ]


def send(url, traces, batch=50):
    endpoint = f"{url.rstrip('/')}/v1/traces"
    written, pending = 0, []

    def flush():
        nonlocal written
        if not pending:
            return
        body = json.dumps({"resourceSpans": pending}).encode()
        request = urllib.request.Request(
            endpoint, data=body, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=30) as response:
            if response.status >= 300:
                raise RuntimeError(f"Jaeger answered {response.status}")
        written += len(pending)
        pending.clear()

    count = 0
    for resource_spans in traces:
        pending.extend(resource_spans)
        count += 1
        if count % batch == 0:
            flush()
    flush()
    return count


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default=DEFAULT_URL,
                        help="Jaeger's OTLP/HTTP endpoint")
    parser.add_argument("--query-url", default="http://localhost:3200",
                        help="Tempo's query API, for the readiness check")
    parser.add_argument("--traces", type=int, default=200)
    parser.add_argument("--hours", type=float, default=2)
    # A DIFFERENT seed from every other seeder. Copied from the Jaeger one it
    # produced identical trace and span ids with different service names, and
    # the fan-out — correctly, since a trace id is globally unique by
    # construction — merged two unrelated traces into one waterfall. The lab
    # was lying, and it looked exactly like an adapter bug.
    parser.add_argument("--seed", type=int, default=20260806,
                        help="fixed by default, so two runs of the lab "
                             "produce the same data; different from every "
                             "other seeder so ids cannot collide")
    arguments = parser.parse_args()

    try:
        with urllib.request.urlopen(
                f"{arguments.query_url.rstrip('/')}/ready", timeout=10) as response:
            if not response.read().decode().strip().startswith("ready"):
                raise RuntimeError("not ready yet")
    except Exception as exc:
        print(f"Tempo is not reachable at {arguments.query_url}: {exc}",
              file=sys.stderr)
        print("Start it with:  ./lab.sh up tempo", file=sys.stderr)
        return 1

    try:
        written = send(arguments.url,
                       build(arguments.traces, arguments.hours, arguments.seed))
    except urllib.error.HTTPError as exc:
        print(f"Tempo refused the write: {exc.code} {exc.read().decode()[:200]}",
              file=sys.stderr)
        return 1

    services = {service for service, _ in _flatten(GRAPH[0], [])}
    print(f"Wrote {written:,} traces to Tempo across {len(services)} services "
          f"over {arguments.hours}h.")
    print(f"  {arguments.query_url}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
