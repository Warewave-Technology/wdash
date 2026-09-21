"""
What the lab holds right now, asked of the backends themselves.

Three modules here measure WDash against real servers — the dashboard
tables, the number and alert panels, and the group-by offer. Each one asks
about a WINDOW, because every screen in the product opens on one, and each
one guarded itself on whether the backend was REACHABLE.

Those are different questions, and the gap between them is where a day went
on 2026-09-20. The lab was up, healthy and holding 151,500 log documents;
its newest record was seven days old; every window in these tests is
twenty-four hours. Fourteen tests failed on an untouched tree, and what they
said was that the adapters answered nothing — "the lab holds no service
here". The tree was fine. The lab needed seeding.

So the guard asks what it actually depends on: does this backend hold
anything in the window? Asked of the backend directly, over its own HTTP
API, and never through the adapter under test — that is the whole point.
An adapter returning nothing while the backend holds records is the failure
these tests exist to catch, and it must not be able to hide behind the same
sentence that means "go and seed the lab".

`WDASH_REQUIRE_LAB=1` turns a skip into a failure, because a job that
promised a seeded lab must not pass by skipping. `tests/test_lab_is_seeded
.py` is where that promise is kept.
"""

import datetime as dt
import os

import requests

#: Both spellings of each variable: the three modules that read them grew
#: apart, one using WDASH_LAB_LOKI and another WDASH_LAB_LOKI_URL, and a
#: helper that honoured one of them would silently point at localhost on
#: somebody's machine where the other was set.
def _url(*names, default):
    for name in names:
        value = os.environ.get(name)
        if value:
            return value
    return default


ES = _url("WDASH_LAB_URL", "WDASH_LAB_ES", default="http://localhost:9200")
LOKI = _url("WDASH_LAB_LOKI", "WDASH_LAB_LOKI_URL",
            default="http://localhost:3100")
VICTORIALOGS = _url("WDASH_LAB_VICTORIALOGS", "WDASH_LAB_VICTORIALOGS_URL",
                    default="http://localhost:9428")
TEMPO = _url("WDASH_LAB_TEMPO", "WDASH_LAB_TEMPO_URL",
             default="http://localhost:3200")
JAEGER = _url("WDASH_LAB_JAEGER", "WDASH_LAB_JAEGER_URL",
              default="http://localhost:16686")

REQUIRED = os.environ.get("WDASH_REQUIRE_LAB") == "1"

#: name -> (address, the `./lab.sh seed` target behind it)
BACKENDS = {
    "es-logs": (ES, "elasticsearch"),
    "es-traces": (ES, "elasticsearch"),
    "loki": (LOKI, "loki"),
    "victorialogs": (VICTORIALOGS, "victorialogs"),
    "tempo": (TEMPO, "tempo"),
    "jaeger": (JAEGER, "jaeger"),
}

TIMEOUT = 5


def reachable(url, path="/"):
    try:
        return requests.get(f"{url}{path}", timeout=3).status_code < 500
    except Exception:
        return False


def _count(kind, hours):
    """Records this backend holds over the last `hours`, or None.

    None means "could not be asked", which is not zero: a backend that is
    down and a backend that is empty need different sentences, and telling
    somebody to seed a Loki that is not running wastes their afternoon.
    """
    now = dt.datetime.now(dt.timezone.utc)
    start = now - dt.timedelta(hours=hours)
    try:
        if kind in ("es-logs", "es-traces"):
            pattern = "*logs*" if kind == "es-logs" else "*traces*,*apm*"
            answer = requests.post(
                f"{ES}/{pattern}/_count",
                json={"query": {"range": {"@timestamp": {
                    "gte": start.isoformat()}}}}, timeout=TIMEOUT)
            return int(answer.json().get("count", 0))

        if kind == "loki":
            # Loki reports no match count for a range query; an instant
            # count_over_time is the only number it will give.
            answer = requests.get(
                f"{LOKI}/loki/api/v1/query", timeout=TIMEOUT,
                params={"query": f'sum(count_over_time({{service_name=~".+"}}'
                                 f"[{max(1, int(hours * 3600))}s]))"})
            result = answer.json().get("data", {}).get("result", [])
            return int(result[0]["value"][1]) if result else 0

        if kind == "victorialogs":
            answer = requests.get(
                f"{VICTORIALOGS}/select/logsql/query", timeout=TIMEOUT,
                params={"query": f"_time:{max(1, int(hours * 3600))}s "
                                 f"| count()"})
            return int(answer.json().get("count(*)", 0))

        if kind == "tempo":
            # Bounded by the limit, so this is a floor — which is all the
            # guard needs. Tempo makes a block searchable on its blocklist
            # poll; the lab's tempo.yaml shortens that for the same reason
            # this file exists.
            answer = requests.get(
                f"{TEMPO}/api/search", timeout=TIMEOUT,
                params={"q": "{}", "limit": 20,
                        "start": int(start.timestamp()),
                        "end": int(now.timestamp())})
            return len(answer.json().get("traces", []) or [])

        if kind == "jaeger":
            # Jaeger cannot answer "every trace": GET /api/traces without a
            # service is an HTTP 400. So the service list first, then one
            # of them — the same shape the adapter's unfiltered search has.
            services = requests.get(f"{JAEGER}/api/services",
                                    timeout=TIMEOUT).json().get("data") or []
            named = [s for s in services if s != "jaeger"]
            if not named:
                return 0
            found = 0
            for service in named[:3]:
                answer = requests.get(
                    f"{JAEGER}/api/traces", timeout=TIMEOUT,
                    params={"service": service, "limit": 5,
                            "start": int(start.timestamp() * 1_000_000),
                            "end": int(now.timestamp() * 1_000_000)})
                found += len(answer.json().get("data") or [])
                if found:
                    break
            return found
    except Exception:
        return None
    return None


def volume(kind, hours=24):
    """How much `kind` holds over the last `hours`; None when unreachable."""
    if kind not in BACKENDS:
        raise ValueError(f"no such lab backend: {kind}")
    url, _ = BACKENDS[kind]
    probe = {"loki": "/ready", "victorialogs": "/health",
             "tempo": "/ready", "jaeger": "/api/services"}.get(kind, "/")
    if not reachable(url, probe):
        return None
    return _count(kind, hours)


def why_not(*kinds, hours=24):
    """Why these tests cannot measure anything, or None.

    One sentence, naming the backend and the command — a reason that does
    not say what to type is a reason somebody has to go and look up.
    """
    down, empty = [], []
    for kind in kinds:
        held = volume(kind, hours)
        if held is None:
            down.append(f"{kind} at {BACKENDS[kind][0]}")
        elif held <= 0:
            empty.append(kind)
    window = (f"{hours:g} hours" if hours >= 1
              else f"{round(hours * 3600)} seconds")
    said = []
    if down:
        said.append(f"not running: {', '.join(down)} — cd lab && ./lab.sh up "
                    f"{' '.join(sorted({BACKENDS[k][1] for k in kinds}))}")
    if empty:
        targets = sorted({BACKENDS[kind][1] for kind in empty})
        said.append(f"nothing in the last {window} in "
                    f"{', '.join(empty)} — cd lab && ./lab.sh seed "
                    f"{' '.join(targets)}")
    return "; ".join(said) or None


def ready(*kinds, hours=24):
    """(may these tests run, the reason they may not).

    Under WDASH_REQUIRE_LAB=1 the reason is raised rather than returned at
    the point of use — see `tests/test_lab_is_seeded.py`, which fails loudly
    instead, so a promised lab cannot be kept by skipping.
    """
    reason = why_not(*kinds, hours=hours)
    return reason is None, reason or ""
