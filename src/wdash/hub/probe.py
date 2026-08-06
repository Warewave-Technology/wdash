"""
Is this source reachable?

Called from the config page before a source is saved. Finding out that a URL is
wrong by saving it and watching every dashboard go blank is a bad way to learn,
and the fix costs one HTTP request.

Deliberately shallow: it asks the backend to identify itself and reports what
came back. It does not run a query, because a source with no data yet is not a
broken source, and a probe that reported one as the other would train people to
ignore it.

Every failure is reported as a message, never an exception. This runs behind a
form; a stack trace helps nobody standing in front of it.
"""

import requests

TIMEOUT = 5


def probe_source(kind, url, username=None, password=None, verify_certs=True):
    """Returns {ok, message, details} — never raises."""
    if kind == "elasticsearch":
        return _probe_elasticsearch(url, username, password, verify_certs)
    if kind == "loki":
        return _probe_loki(url, username, password, verify_certs)
    if kind == "victorialogs":
        return _probe_victorialogs(url, username, password, verify_certs)
    if kind == "jaeger":
        return _probe_jaeger(url, username, password, verify_certs)
    if kind == "tempo":
        return _probe_tempo(url, username, password, verify_certs)
    return {"ok": False, "message": f"No connection test for '{kind}'."}


def _request(url, username, password, verify_certs):
    auth = (username, password) if username else None
    return requests.get(url, auth=auth, timeout=TIMEOUT, verify=verify_certs)


def _probe_elasticsearch(url, username, password, verify_certs):
    try:
        response = _request(url.rstrip("/") + "/", username, password, verify_certs)
    except requests.exceptions.SSLError as exc:
        return {"ok": False,
                "message": "TLS verification failed. Check the certificate, or "
                           "turn off verification if this is a self-signed "
                           "development cluster.",
                "details": str(exc)[:200]}
    except requests.exceptions.ConnectTimeout:
        return {"ok": False, "message": f"No response within {TIMEOUT} seconds."}
    except requests.exceptions.RequestException as exc:
        return {"ok": False, "message": "Could not connect.",
                "details": str(exc)[:200]}

    if response.status_code == 401:
        return {"ok": False,
                "message": "Reached the cluster, but the credentials were "
                           "rejected."}
    if response.status_code == 403:
        return {"ok": False,
                "message": "Reached the cluster, but this user is not allowed "
                           "to read cluster information."}
    if response.status_code >= 400:
        return {"ok": False,
                "message": f"The cluster answered with HTTP {response.status_code}."}

    try:
        body = response.json()
        version = (body.get("version") or {}).get("number")
        # The distribution matters: OpenSearch answers this endpoint too, and
        # some rules and APIs differ.
        distribution = (body.get("version") or {}).get("distribution", "elasticsearch")
        name = body.get("cluster_name")
    except ValueError:
        return {"ok": False,
                "message": "Something answered, but it does not look like "
                           "Elasticsearch."}

    if not version:
        return {"ok": False,
                "message": "Something answered, but it does not look like "
                           "Elasticsearch."}

    return {"ok": True,
            "message": f"Connected to {distribution} {version}"
                       + (f" ({name})" if name else ""),
            "details": {"version": version, "distribution": distribution,
                        "cluster_name": name}}


def _probe_loki(url, username, password, verify_certs):
    # /ready is Loki's own readiness endpoint and needs no query permissions.
    try:
        response = _request(url.rstrip("/") + "/ready", username, password,
                            verify_certs)
    except requests.exceptions.SSLError as exc:
        return {"ok": False, "message": "TLS verification failed.",
                "details": str(exc)[:200]}
    except requests.exceptions.RequestException as exc:
        return {"ok": False, "message": "Could not connect.",
                "details": str(exc)[:200]}

    if response.status_code == 401:
        return {"ok": False,
                "message": "Reached Loki, but the credentials were rejected."}
    if response.status_code >= 400:
        return {"ok": False,
                "message": f"Loki answered with HTTP {response.status_code}."}

    text = (response.text or "").strip()
    if "ready" not in text.lower():
        return {"ok": False,
                "message": "Something answered, but it does not look like Loki."}
    return {"ok": True, "message": "Connected to Loki (ready)."}


def _probe_victorialogs(url, username, password, verify_certs):
    # /health needs no query permissions and no LogsQL, so a failure here is
    # about reachability rather than about the query being wrong.
    try:
        response = _request(url.rstrip("/") + "/health", username, password,
                            verify_certs)
    except requests.exceptions.SSLError as exc:
        return {"ok": False, "message": "TLS verification failed.",
                "details": str(exc)[:200]}
    except requests.exceptions.RequestException as exc:
        return {"ok": False, "message": "Could not connect.",
                "details": str(exc)[:200]}

    if response.status_code == 401:
        return {"ok": False, "message": "Reached VictoriaLogs, but the "
                                        "credentials were rejected."}
    if response.status_code >= 400:
        return {"ok": False,
                "message": f"VictoriaLogs answered with HTTP "
                           f"{response.status_code}."}

    # VictoriaMetrics answers /health with "OK" too, and it is a completely
    # different API — pointing a log source at it would fail on every search
    # with an error about LogsQL that nobody would connect to this screen.
    if "OK" not in (response.text or ""):
        return {"ok": False,
                "message": "Something answered, but it does not look like "
                           "VictoriaLogs."}
    try:
        probe = _request(url.rstrip("/") + "/select/logsql/field_names?query=*",
                         username, password, verify_certs)
    except requests.exceptions.RequestException as exc:
        return {"ok": False,
                "message": "Healthy, but the query API did not answer.",
                "details": str(exc)[:200]}
    if probe.status_code >= 400:
        return {"ok": False,
                "message": "Healthy, but this is not a VictoriaLogs query "
                           "endpoint."}
    return {"ok": True, "message": "Connected to VictoriaLogs."}


def _probe_jaeger(url, username, password, verify_certs):
    # `/api/services` needs no trace data and no query permissions, so a
    # failure here is about reachability rather than about the query.
    try:
        response = _request(url.rstrip("/") + "/api/services", username,
                            password, verify_certs)
    except requests.exceptions.SSLError as exc:
        return {"ok": False, "message": "TLS verification failed.",
                "details": str(exc)[:200]}
    except requests.exceptions.RequestException as exc:
        return {"ok": False, "message": "Could not connect.",
                "details": str(exc)[:200]}

    if response.status_code == 401:
        return {"ok": False,
                "message": "Reached it, but the credentials were rejected."}
    if response.status_code >= 400:
        return {"ok": False,
                "message": f"Jaeger answered with HTTP {response.status_code}."}

    # The UI and the API are on the same port, so a URL pointing at something
    # else entirely can still answer 200. `data` is what makes it Jaeger.
    try:
        body = response.json()
    except ValueError:
        return {"ok": False,
                "message": "Something answered, but not with JSON. This is the "
                           "query API port, not the UI."}
    if "data" not in body:
        return {"ok": False,
                "message": "Something answered, but it does not look like "
                           "Jaeger."}

    services = body.get("data") or []
    return {"ok": True,
            "message": f"Connected to Jaeger ({len(services)} service"
                       f"{'' if len(services) == 1 else 's'})."}


def _probe_tempo(url, username, password, verify_certs):
    try:
        response = _request(url.rstrip("/") + "/ready", username, password,
                            verify_certs)
    except requests.exceptions.SSLError as exc:
        return {"ok": False, "message": "TLS verification failed.",
                "details": str(exc)[:200]}
    except requests.exceptions.RequestException as exc:
        return {"ok": False, "message": "Could not connect.",
                "details": str(exc)[:200]}

    if response.status_code == 401:
        return {"ok": False,
                "message": "Reached it, but the credentials were rejected."}
    if response.status_code >= 400:
        return {"ok": False,
                "message": f"Tempo answered with HTTP {response.status_code}."}

    # Tempo answers `/ready` with 200 and a body that says otherwise while it
    # is starting: "Ingester not ready: waiting for 15s after being ready".
    # A status code alone would report a starting Tempo as connected.
    text = (response.text or "").strip()
    if not text.startswith("ready"):
        return {"ok": False,
                "message": "Reached it, but it is not ready yet.",
                "details": text[:200]}
    return {"ok": True, "message": "Connected to Tempo."}
