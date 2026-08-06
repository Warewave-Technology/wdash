"""
Push real OTLP traces and logs through the collector.

Not a seeder. The seed writes documents straight into Elasticsearch in the
shape WDash expects; this sends OTLP over the wire and lets the collector
decide what lands. The difference is the entire point — one tests the adapter
against our assumptions, the other against the ecosystem.

    ./lab.sh up otel
    PYTHONPATH=. python lab/otel/emit.py

Uses the OTLP/HTTP endpoint and a hand-built protobuf-free JSON payload so the
lab needs no OpenTelemetry SDK. OTLP/HTTP accepts JSON, which is exactly the
sort of thing that makes a protocol testable.
"""

import argparse
import json
import random
import sys
import time
import urllib.error
import urllib.request
import uuid

SERVICES = ["api-gateway", "payment-service", "auth-service", "postgres"]


def _hex(length):
    return uuid.uuid4().hex[:length]


def _now_ns():
    return int(time.time() * 1_000_000_000)


def _attribute(key, value):
    if isinstance(value, bool):
        return {"key": key, "value": {"boolValue": value}}
    if isinstance(value, int):
        return {"key": key, "value": {"intValue": str(value)}}
    return {"key": key, "value": {"stringValue": str(value)}}


def build_trace(now_ns):
    """One trace: a root server span with a few children."""
    trace_id = _hex(32)
    root_id = _hex(16)
    root_duration = random.randint(40, 900) * 1_000_000        # ns
    failed = random.random() < 0.15

    spans = [{
        "traceId": trace_id, "spanId": root_id, "name": "GET /checkout",
        "kind": 2,                                             # SPAN_KIND_SERVER
        "startTimeUnixNano": str(now_ns),
        "endTimeUnixNano": str(now_ns + root_duration),
        "attributes": [_attribute("http.request.method", "GET"),
                       _attribute("http.response.status_code",
                                  500 if failed else 200)],
        "status": {"code": 2 if failed else 1},                # ERROR / OK
    }]

    offset = 2_000_000
    for index in range(random.randint(1, 3)):
        child_duration = random.randint(5, root_duration // 1_000_000 or 1) * 1_000_000
        spans.append({
            "traceId": trace_id, "spanId": _hex(16), "parentSpanId": root_id,
            "name": random.choice(["SELECT orders", "GET /profile", "SETEX cache"]),
            "kind": 3,                                         # SPAN_KIND_CLIENT
            "startTimeUnixNano": str(now_ns + offset),
            "endTimeUnixNano": str(now_ns + offset + child_duration),
            "attributes": [_attribute("db.system", "postgresql")],
            "status": {"code": 1},
        })
        offset += child_duration

    return trace_id, {
        "resourceSpans": [{
            "resource": {"attributes": [
                _attribute("service.name", random.choice(SERVICES)),
                _attribute("service.version", "1.4.2"),
                _attribute("deployment.environment", "lab"),
            ]},
            "scopeSpans": [{"spans": spans}],
        }]
    }


def build_logs(now_ns, trace_id):
    """Log records carrying the same trace id, so correlation is exercised."""
    severity = random.choice([
        (9, "INFO"), (9, "INFO"), (13, "WARN"), (17, "ERROR")])
    return {
        "resourceLogs": [{
            "resource": {"attributes": [
                _attribute("service.name", random.choice(SERVICES)),
                _attribute("deployment.environment", "lab"),
            ]},
            "scopeLogs": [{"logRecords": [{
                "timeUnixNano": str(now_ns),
                "severityNumber": severity[0],
                "severityText": severity[1],
                "body": {"stringValue": random.choice([
                    "checkout completed",
                    "upstream timeout after 5s",
                    "token refreshed",
                    "connection pool exhausted"])},
                "traceId": trace_id,
                "attributes": [_attribute("request_id", _hex(8))],
            }]}],
        }]
    }


def post(url, payload, timeout=10):
    request = urllib.request.Request(
        url, data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, response.read().decode("utf-8")[:200]
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode("utf-8")[:200]
    except urllib.error.URLError as error:
        return None, str(error.reason)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", default="http://localhost:4318")
    parser.add_argument("--traces", type=int, default=25)
    parser.add_argument("--spread-minutes", type=int, default=30,
                        help="scatter the timestamps back over this many minutes")
    arguments = parser.parse_args(argv)

    now_ns = _now_ns()
    spread_ns = arguments.spread_minutes * 60 * 1_000_000_000

    sent = failed = 0
    for index in range(arguments.traces):
        at = now_ns - random.randint(0, spread_ns)
        trace_id, payload = build_trace(at)

        status, body = post(f"{arguments.endpoint}/v1/traces", payload)
        if status != 200:
            failed += 1
            print(f"  trace rejected: {status} {body}", file=sys.stderr)
            continue

        status, body = post(f"{arguments.endpoint}/v1/logs",
                            build_logs(at, trace_id))
        if status != 200:
            failed += 1
            print(f"  logs rejected: {status} {body}", file=sys.stderr)
            continue
        sent += 1

    print(f"Sent {sent} traces with correlated logs "
          f"via OTLP/HTTP to {arguments.endpoint}"
          + (f" ({failed} rejected)" if failed else ""))
    return 1 if failed and not sent else 0


if __name__ == "__main__":
    sys.exit(main())
