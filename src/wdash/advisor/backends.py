"""
Snapshots of the backends that are not Elasticsearch.

The Advisor's design rule holds: rules are pure functions over a snapshot and
never talk to a backend. Everything that speaks HTTP lives here, so a rule can
be tested against a saved dictionary and a collector can fail without taking
the report down.

What each backend can be asked about differs a great deal, and pretending
otherwise would be the worst outcome:

    Loki           `/config` returns the entire effective configuration
    VictoriaLogs   `/flags` returns the command line it was started with
    Tempo          `/status/config` returns the effective configuration
    Jaeger         nothing. Its query API describes traces, not itself

That last one is not a gap to paper over. Jaeger exposes Prometheus metrics on
a separate admin port that a deployment may not publish, and demanding a
second URL from everybody to serve one advisor is a worse trade than saying
plainly that there is little to check. Its rules therefore work from what the
query API can answer — how many services exist, and whether the metrics API is
available — and the report says so.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone

import requests

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 15


@dataclass
class SourceSnapshot:
    """What a non-Elasticsearch backend could be persuaded to say about itself.

    Deliberately shaped like `ClusterSnapshot` where the report needs it —
    `cluster_name`, `version`, `distribution`, `errors` — so `run_rules` does
    not need to know which kind it has.
    """

    backend: str
    source_name: str
    taken_at: str = ""
    #: The effective configuration, as the backend reports it. Shape differs
    #: per backend; each rule module knows its own.
    settings: dict = field(default_factory=dict)
    #: Observations that are not configuration — a service count, a version.
    facts: dict = field(default_factory=dict)
    errors: dict = field(default_factory=dict)

    # ---------------- identity, for the report ----------------

    @property
    def cluster_name(self):
        return self.source_name

    @property
    def version(self):
        return str(self.facts.get("version") or "unknown")

    @property
    def distribution(self):
        return self.backend

    @property
    def version_tuple(self):
        """Rules here do not gate on version; the property exists because the
        report's applicability check reads it."""
        parts = []
        for piece in str(self.facts.get("version") or "").split("."):
            digits = "".join(c for c in piece if c.isdigit())
            if not digits:
                break
            parts.append(int(digits))
        return tuple(parts)

    # ---------------- reading ----------------

    def setting(self, path, default=None):
        """A dotted path into the effective configuration.

        Missing is not the same as false: a rule that cannot see a setting
        should skip rather than claim it is off, so this returns the default
        and the rules check for `None` explicitly.
        """
        current = self.settings
        for part in path.split("."):
            if not isinstance(current, dict) or part not in current:
                return default
            current = current[part]
        return current


def _now():
    return datetime.now(timezone.utc).isoformat()


def _get(session, url, timeout=DEFAULT_TIMEOUT, **kwargs):
    response = (session or requests).get(url, timeout=timeout, **kwargs)
    response.raise_for_status()
    return response


def _yaml_document(text):
    """Parse a YAML body that may carry a header line before the document.

    Tempo answers `/status/config` with `GET /status/config\\n---\\n…`, which
    is two documents to a YAML parser and an error to a naive one.
    """
    import yaml

    documents = [d for d in yaml.safe_load_all(text) if isinstance(d, dict)]
    return documents[0] if documents else {}


# ---------------------------------------------------------------------------
# Collectors
# ---------------------------------------------------------------------------

def collect_loki(url, name, session=None, auth=None, verify=True,
                 timeout=DEFAULT_TIMEOUT):
    """Loki's effective configuration, from `/config`."""
    snapshot = SourceSnapshot(backend="loki", source_name=name,
                              taken_at=_now())
    base = url.rstrip("/")

    try:
        response = _get(session, f"{base}/config", timeout, auth=auth,
                        verify=verify)
        snapshot.settings = _yaml_document(response.text) or {}
    except Exception as exc:
        snapshot.errors["config"] = str(exc)[:200]

    try:
        response = _get(session, f"{base}/loki/api/v1/status/buildinfo",
                        timeout, auth=auth, verify=verify)
        snapshot.facts["version"] = (response.json() or {}).get("version")
    except Exception as exc:
        snapshot.errors["buildinfo"] = str(exc)[:200]

    return snapshot


def collect_victorialogs(url, name, session=None, auth=None, verify=True,
                         timeout=DEFAULT_TIMEOUT):
    """VictoriaLogs' command line, from `/flags`.

    `/flags` reports only the flags that were SET, not every flag with its
    default. So an absent flag means "left at the default", which is exactly
    what several of the rules are about — and why they check for absence
    rather than for a value.
    """
    snapshot = SourceSnapshot(backend="victorialogs", source_name=name,
                              taken_at=_now())
    base = url.rstrip("/")

    try:
        response = _get(session, f"{base}/flags", timeout, auth=auth,
                        verify=verify)
        flags = {}
        for line in response.text.splitlines():
            line = line.strip()
            if not line.startswith("-"):
                continue
            key, _, value = line[1:].partition("=")
            flags[key.strip()] = value.strip().strip('"')
        snapshot.settings = flags
    except Exception as exc:
        snapshot.errors["flags"] = str(exc)[:200]

    try:
        response = _get(session, f"{base}/metrics", timeout, auth=auth,
                        verify=verify)
        snapshot.facts.update(_prometheus(response.text, (
            "vl_free_disk_space_bytes",
            "vl_data_size_bytes",
        )))
        # The version travels as a LABEL on a gauge whose value is always 1,
        # which is the Prometheus convention and not something the numeric
        # parser above can read.
        import re
        match = re.search(r'vm_app_version\{[^}]*short_version="([^"]+)"',
                          response.text)
        if match:
            snapshot.facts["version"] = match.group(1)
    except Exception as exc:
        snapshot.errors["metrics"] = str(exc)[:200]

    return snapshot


def collect_tempo(url, name, session=None, auth=None, verify=True,
                  timeout=DEFAULT_TIMEOUT):
    """Tempo's effective configuration, from `/status/config`."""
    snapshot = SourceSnapshot(backend="tempo", source_name=name,
                              taken_at=_now())
    base = url.rstrip("/")

    try:
        response = _get(session, f"{base}/status/config", timeout, auth=auth,
                        verify=verify)
        snapshot.settings = _yaml_document(response.text) or {}
    except Exception as exc:
        snapshot.errors["config"] = str(exc)[:200]

    try:
        response = _get(session, f"{base}/status/version", timeout, auth=auth,
                        verify=verify)
        # `tempo, version 2.6.1 (branch: …)` on the line after the header,
        # followed by a build-info block. Taking the LAST line gave "tags:
        # unknown", which is a version number nobody would recognise as wrong.
        import re
        # Anchored on the digits, not on the word "version": the body starts
        # with `GET /status/version`, so a loose match read the URL and
        # reported the version as "tempo,".
        match = re.search(r"version\s+(\d[\w.\-]*)", response.text)
        snapshot.facts["version"] = match.group(1) if match else "unknown"
    except Exception as exc:
        snapshot.errors["version"] = str(exc)[:200]

    return snapshot


def collect_jaeger(url, name, session=None, auth=None, verify=True,
                   timeout=DEFAULT_TIMEOUT):
    """What Jaeger's query API can say about the deployment.

    Which is not much, and the rules are honest about it. Everything richer
    lives on an admin port that a deployment may not publish.
    """
    snapshot = SourceSnapshot(backend="jaeger", source_name=name,
                              taken_at=_now())
    base = url.rstrip("/")

    try:
        response = _get(session, f"{base}/api/services", timeout, auth=auth,
                        verify=verify)
        services = (response.json() or {}).get("data") or []
        snapshot.facts["services"] = [s for s in services if s]
    except Exception as exc:
        snapshot.errors["services"] = str(exc)[:200]

    # Not an error when it refuses: HTTP 501 is Jaeger saying the metrics
    # backend is not wired up, which is a finding rather than a collection
    # failure.
    try:
        response = (session or requests).get(
            f"{base}/api/metrics/calls", params={"service": "any"},
            timeout=timeout, auth=auth, verify=verify)
        snapshot.facts["metrics_api"] = response.status_code
    except Exception as exc:
        snapshot.errors["metrics"] = str(exc)[:200]

    return snapshot


COLLECTORS = {
    "loki": collect_loki,
    "victorialogs": collect_victorialogs,
    "tempo": collect_tempo,
    "jaeger": collect_jaeger,
}


def collect(kind, url, name, **kwargs):
    """Snapshot one configured source, or None when nothing can be checked."""
    collector = COLLECTORS.get(kind)
    if collector is None:
        return None
    return collector(url, name, **kwargs)


def _prometheus(text, wanted):
    """Pull a few named gauges out of a Prometheus exposition body.

    A parser rather than a regular expression per metric, because the label
    set varies and `metric{a="b"} 1` and `metric 1` are both valid.
    """
    out = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        name = line.split("{", 1)[0].split(" ", 1)[0]
        if name not in wanted:
            continue
        value = line.rsplit(" ", 1)[-1]
        try:
            out[name] = float(value)
        except ValueError:
            # A version gauge carries its value in a label; keep the raw line
            # so a rule can read what it needs.
            out[name] = line
    return out
