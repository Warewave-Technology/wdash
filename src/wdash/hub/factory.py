"""
Turning stored source definitions into live sources.

The config page writes a row; this reads it back and builds the adapter. Kept
separate from both so that neither knows about the other: the repository stores
configuration without knowing what a hub is, and the adapter takes a client
without knowing where its credentials came from.

Failure policy: one broken source must not stop WDash from starting. A wrong
password on the trace store should cost the trace screen, not the whole
application — and the reason has to reach the logs, because a source that
silently does not exist looks exactly like a source with no data.
"""

import logging

logger = logging.getLogger(__name__)


def _elasticsearch_client(config, password):
    from elasticsearch import Elasticsearch

    arguments = {"hosts": [config["url"]], "request_timeout": 30}
    if config.get("username"):
        arguments["basic_auth"] = (config["username"], password or "")
    if not config.get("verify_certs", True):
        arguments["verify_certs"] = False
        arguments["ssl_show_warn"] = False
    return Elasticsearch(**arguments)


def _signal_config(config, signal, field, default=()):
    """A per-signal setting, falling back to the flat one.

    Sources written before a source could serve two signals keep their
    patterns at the top level. Reading the nested block first and the flat one
    second means an existing row behaves exactly as it did, and a new row gets
    a pattern per signal.
    """
    block = config.get(signal)
    if isinstance(block, dict) and field in block:
        return tuple(block[field] or ())
    return tuple(config.get(field) or default)


def build_source(record, credential, catalogue=None, signal=None):
    """Build one adapter from a stored definition, for one signal."""
    from .adapters import ElasticsearchLogSource, ElasticsearchTraceSource

    kind, config = record["kind"], record["config"]
    signal = signal or (record.get("signals") or [record["signal"]])[0]

    if kind == "elasticsearch":
        client = _elasticsearch_client(config, credential)
        patterns = _signal_config(config, signal, "index_patterns", ("*",))
        excludes = _signal_config(config, signal, "exclude_patterns")
        if signal == "logs":
            return ElasticsearchLogSource(client, name=record["name"],
                                          patterns=patterns or ("*",),
                                          exclude=excludes,
                                          catalogue=catalogue)
        if signal == "monitors":
            from .adapters.es_monitors import (
                DEFAULT_PATTERNS, ElasticsearchMonitorSource,
            )
            # Read AGAIN, without the `("*",)` default above. `patterns` is
            # never empty by the time it gets here, so `patterns or
            # DEFAULT_PATTERNS` would always take the first branch and every
            # monitor listing would scan every index in the cluster to find
            # nothing — slowly, and looking like "no monitors configured".
            configured = _signal_config(config, signal, "index_patterns", ())
            return ElasticsearchMonitorSource(
                client, name=record["name"],
                patterns=tuple(configured) or DEFAULT_PATTERNS,
                catalogue=catalogue)
        return ElasticsearchTraceSource(client, name=record["name"],
                                        patterns=patterns or ("*",),
                                        catalogue=catalogue)

    if kind == "loki":
        from .adapters.loki import LokiLogSource

        if signal != "logs":
            raise ValueError("Loki serves logs only")
        return LokiLogSource(
            url=config["url"], name=record["name"],
            stream_label=config.get("stream_label") or "service_name",
            username=config.get("username") or None, password=credential,
            tenant=config.get("tenant") or None,
            verify_certs=config.get("verify_certs", True))

    if kind == "jaeger":
        from .adapters.jaeger import JaegerTraceSource

        if signal != "traces":
            raise ValueError("Jaeger serves traces only")
        return JaegerTraceSource(
            url=config["url"], name=record["name"],
            username=config.get("username") or None, password=credential,
            tenant=config.get("tenant") or None,
            verify_certs=config.get("verify_certs", True))

    if kind == "tempo":
        from .adapters.tempo import TempoTraceSource

        if signal != "traces":
            raise ValueError("Tempo serves traces only")
        return TempoTraceSource(
            url=config["url"], name=record["name"],
            username=config.get("username") or None, password=credential,
            tenant=config.get("tenant") or None,
            verify_certs=config.get("verify_certs", True))

    if kind == "victorialogs":
        from .adapters.victorialogs import VictoriaLogsSource

        if signal != "logs":
            raise ValueError("VictoriaLogs serves logs only")
        return VictoriaLogsSource(
            url=config["url"], name=record["name"],
            stream_field=config.get("stream_field") or "service",
            username=config.get("username") or None, password=credential,
            tenant=config.get("tenant") or None,
            verify_certs=config.get("verify_certs", True))

    raise ValueError(f"Unknown source type: {kind}")


def build_configured_sources(store, catalogue=None):
    """Every enabled stored source, built, grouped by signal.

    Separate from registering them because the hub reloads this set without a
    restart: it needs the sources in hand before it swaps them in, so that a
    store it cannot read leaves the previous ones running rather than taking
    them all away.
    """
    built = {"logs": [], "traces": [], "monitors": []}
    for record in store.sources.all(enabled_only=True):
        try:
            credential = store.sources.credential(record["id"])
        except Exception as exc:
            logger.error(f"Source '{record['name']}': {exc}")
            continue

        # One row, one adapter per signal it serves. An Elasticsearch cluster
        # holding both used to need two rows — two credentials to rotate, two
        # TLS settings that could drift, two health entries for one system.
        for signal in record.get("signals") or [record["signal"]]:
            try:
                source = build_source(record, credential, catalogue, signal)
            except NotImplementedError as exc:
                logger.warning(
                    f"Source '{record['name']}' cannot serve {signal}: {exc}")
                continue
            except Exception as exc:
                # Never fatal, and per signal: a broken trace pattern must not
                # take the same source's log side down with it.
                logger.error(
                    f"Source '{record['name']}' ({signal}) could not be "
                    f"built: {exc}")
                continue

            built["logs" if signal == "logs"
                  else "monitors" if signal == "monitors"
                  else "traces"].append(source)
            logger.info(
                f"Built {signal} source '{record['name']}' "
                f"({record['kind']})")

    return built


def register_configured_sources(hub, store, catalogue=None):
    """Add every enabled stored source to the hub, once.

    Returns the number registered. Kept for callers that want a hub loaded
    and left alone; the application uses `Hub.reload_with` instead, so that
    saving the configuration page does not need a restart to take effect.
    """
    built = build_configured_sources(store, catalogue)
    for source in built["logs"]:
        hub.add_logs(source)
    for source in built["traces"]:
        hub.add_traces(source)
    for source in built["monitors"]:
        hub.add_monitors(source)
    return sum(len(group) for group in built.values())
