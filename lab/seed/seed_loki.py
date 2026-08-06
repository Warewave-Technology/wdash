#!/usr/bin/env python3
"""
Sample logs for the lab's Loki.

Separate from `seed.py` and `seed_victorialogs.py` for the same reason those
two are separate from each other: three transports in one script makes "which
one failed" a question you answer by reading code.

The services here are again distinct from the other two backends, so a merged
search draws visibly from all three and the per-source breakdown has something
to say. Loki's own limits are on display by design — it reports no match count
for a range query, so its total in a merged page is a floor and WDash says so.

    python3 seed_loki.py                  # 2,000 lines over 24 hours
    python3 seed_loki.py --hours 168      # a week
"""

import argparse
import datetime as dt
import json
import random
import sys
import urllib.error
import urllib.request

DEFAULT_URL = "http://localhost:3100"

#: Not the names the Elasticsearch or VictoriaLogs seeds use.
SERVICES = ("edge-router", "session-svc", "billing-api", "media-worker")

MESSAGES = (
    ("info", 55, "{method} {path} {status} in {ms}ms"),
    ("info", 18, "queue drained, {n} messages"),
    ("warn", 14, "backpressure on {path}, depth {n}"),
    ("error", 9, "handler panic on {path}"),
    ("error", 4, "tls handshake failed with {peer}"),
)

METHODS = ("GET", "POST", "PUT")
PATHS = ("/session", "/billing/invoice", "/media/upload", "/edge/route",
         "/healthz")


def build(count, hours, seed):
    """Streams keyed by (service_name, level), as Loki wants them.

    Loki refuses out-of-order lines within a stream on older configurations
    and is unhappy about them generally, so each stream's values are sorted
    before they are sent rather than emitted in the order they were invented.
    """
    random.seed(seed)
    now = dt.datetime.now(dt.timezone.utc)
    streams = {}

    weights = [entry[1] for entry in MESSAGES]
    for _ in range(count):
        level, _, template = random.choices(MESSAGES, weights=weights)[0]
        service = random.choice(SERVICES)
        moment = now - dt.timedelta(seconds=random.random() * hours * 3600)

        message = template.format(
            method=random.choice(METHODS),
            path=random.choice(PATHS),
            status=random.choice((200, 200, 201, 204, 400, 404, 502)),
            ms=random.randint(2, 3800),
            n=random.randint(1, 500),
            peer=random.choice([s for s in SERVICES if s != service]),
        )
        line = json.dumps({"msg": message, "level": level,
                           "host": f"{service}-{random.randint(1, 3)}"})
        key = (service, level)
        streams.setdefault(key, []).append(
            (str(int(moment.timestamp() * 1_000_000_000)), line))

    return [
        {"stream": {"service_name": service, "level": level},
         "values": sorted(values, key=lambda pair: int(pair[0]))}
        for (service, level), values in streams.items()
    ]


def send(url, streams):
    endpoint = f"{url.rstrip('/')}/loki/api/v1/push"
    body = json.dumps({"streams": streams}).encode()
    request = urllib.request.Request(
        endpoint, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=60) as response:
        if response.status >= 300:
            raise RuntimeError(f"Loki answered {response.status}")
    return sum(len(stream["values"]) for stream in streams)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default=DEFAULT_URL)
    parser.add_argument("--logs", type=int, default=2000)
    parser.add_argument("--hours", type=int, default=24)
    parser.add_argument("--seed", type=int, default=20260807,
                        help="fixed by default, so two runs of the lab "
                             "produce the same data; different from every "
                             "other seeder so ids cannot collide")
    arguments = parser.parse_args()

    try:
        with urllib.request.urlopen(f"{arguments.url.rstrip('/')}/ready",
                                    timeout=10) as response:
            if "ready" not in response.read().decode().lower():
                raise RuntimeError("not ready")
    except Exception as exc:
        print(f"Loki is not reachable at {arguments.url}: {exc}",
              file=sys.stderr)
        print("Start it with:  ./lab.sh up loki", file=sys.stderr)
        return 1

    try:
        written = send(arguments.url,
                       build(arguments.logs, arguments.hours, arguments.seed))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode()[:300]
        print(f"Loki refused the write: {exc.code} {detail}", file=sys.stderr)
        # The usual cause, and the message Loki gives for it is not obvious.
        if "too far behind" in detail or "too old" in detail:
            print("Lines older than Loki's reject_old_samples_max_age are "
                  "refused. Use a shorter --hours.", file=sys.stderr)
        return 1

    print(f"Wrote {written:,} lines to Loki across {len(SERVICES)} services "
          f"over {arguments.hours}h.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
