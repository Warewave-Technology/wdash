#!/usr/bin/env python3
"""
Sample logs for the lab's VictoriaLogs.

Separate from `seed.py` because it writes somewhere else entirely: `seed.py`
speaks to Elasticsearch, and mixing two transports into one script makes
"which half failed" a question you have to read code to answer.

The point of this data is not volume — it is having a second log backend with
DIFFERENT service names from Elasticsearch, so that a merged search visibly
draws from both and a per-source breakdown has something to show.

    python3 seed_victorialogs.py                 # 2,000 lines over 24 hours
    python3 seed_victorialogs.py --hours 168     # a week, for range testing
"""

import argparse
import datetime as dt
import json
import random
import sys
import urllib.error
import urllib.request

DEFAULT_URL = "http://localhost:9428"

#: Deliberately not the same services the Elasticsearch seed writes. A merged
#: search over two backends that both say "api-gateway" cannot show you that
#: the merge is working.
SERVICES = ("checkout-api", "payment-service", "shipping-svc", "search-svc",
            "auth-service")

#: (level, weight, template). The weights make errors rare enough that finding
#: them is a search rather than a scroll.
MESSAGES = (
    ("info", 60, "{method} {path} {status} in {ms}ms"),
    ("info", 15, "cache hit for key {key}"),
    ("warn", 12, "slow query took {ms}ms on {path}"),
    ("warn", 5, "retrying {path} after upstream 503"),
    ("error", 6, "upstream timeout talking to {peer}"),
    ("error", 2, "database connection refused"),
)

METHODS = ("GET", "POST", "PUT", "DELETE")
PATHS = ("/orders", "/orders/{id}", "/cart", "/checkout", "/search",
         "/health", "/users/{id}")


def build(count, hours, seed):
    random.seed(seed)
    now = dt.datetime.now(dt.timezone.utc)
    levels = [entry for entry in MESSAGES]
    weights = [entry[1] for entry in levels]

    for index in range(count):
        level, _, template = random.choices(levels, weights=weights)[0]
        service = random.choice(SERVICES)
        # Spread over the window, newest last.
        moment = now - dt.timedelta(
            seconds=random.random() * hours * 3600)

        # Every placeholder the template might use, so a template change
        # cannot leave a stray `{peer}` in the output.
        message = template.format(
            method=random.choice(METHODS),
            path=random.choice(PATHS).replace("{id}", str(random.randint(1, 9999))),
            status=random.choice((200, 200, 200, 201, 204, 400, 404, 500)),
            ms=random.randint(2, 4200),
            key=f"sess:{random.randint(1000, 9999)}",
            peer=random.choice([s for s in SERVICES if s != service]),
        )

        yield {
            "_time": moment.isoformat(),
            "_msg": message,
            "service": service,
            "level": level,
            "host": f"{service}-{random.randint(1, 3)}",
            "env": "lab",
            # A quarter of the lines carry a trace id, which is what makes the
            # log-to-trace jump testable rather than uniformly present.
            **({"trace_id": f"{random.getrandbits(64):016x}"}
               if random.random() < 0.25 else {}),
        }


def send(url, rows, batch=500):
    """Write in batches over the JSON-lines ingestion endpoint."""
    endpoint = (f"{url.rstrip('/')}/insert/jsonline"
                f"?_stream_fields=service,level&_time_field=_time"
                f"&_msg_field=_msg")
    written, pending = 0, []

    def flush():
        nonlocal written
        if not pending:
            return
        body = "\n".join(json.dumps(row) for row in pending).encode()
        request = urllib.request.Request(
            endpoint, data=body,
            headers={"Content-Type": "application/stream+json"})
        with urllib.request.urlopen(request, timeout=30) as response:
            if response.status >= 300:
                raise RuntimeError(f"VictoriaLogs answered {response.status}")
        written += len(pending)
        pending.clear()

    for row in rows:
        pending.append(row)
        if len(pending) >= batch:
            flush()
    flush()
    return written


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default=DEFAULT_URL)
    parser.add_argument("--logs", type=int, default=2000,
                        help="how many lines to write")
    parser.add_argument("--hours", type=int, default=24,
                        help="how far back to spread them")
    parser.add_argument("--seed", type=int, default=20260808,
                        help="fixed by default, so two runs of the lab "
                             "produce the same data and a difference means "
                             "something changed")
    arguments = parser.parse_args()

    try:
        with urllib.request.urlopen(f"{arguments.url.rstrip('/')}/health",
                                    timeout=10) as response:
            if "OK" not in response.read().decode():
                raise RuntimeError("health check did not answer OK")
    except Exception as exc:
        print(f"VictoriaLogs is not reachable at {arguments.url}: {exc}",
              file=sys.stderr)
        print("Start it with:  ./lab.sh up victorialogs", file=sys.stderr)
        return 1

    written = send(arguments.url,
                   build(arguments.logs, arguments.hours, arguments.seed))
    print(f"Wrote {written:,} lines to VictoriaLogs across "
          f"{len(SERVICES)} services over {arguments.hours}h.")
    print(f"  {arguments.url}/select/vmui")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
