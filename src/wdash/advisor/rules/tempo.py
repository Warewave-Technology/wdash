"""
Tempo checks.

Tempo's `/status/config` reports the effective configuration, so these rules
read the same values an operator would. The ones here are about durability and
about the two features people expect Tempo to have and then find switched off.
"""

from ..models import Finding, NotEvaluated, Severity, rule

TEMPO = ("tempo",)
DOCS = "https://grafana.com/docs/tempo/latest/configuration/"
#: Every rule here reads `/status/config`.
CONFIG = ("config",)


def _setting(snapshot, path):
    """A setting from `/status/config`, the effective configuration: one that
    is not there could not be read, and the rule has no verdict."""
    value = snapshot.setting(path)
    if value is None:
        raise NotEvaluated(f"{path} is not in /status/config")
    return value

#: Backends that survive losing the machine. `local` does not, and it is what
#: every getting-started configuration uses.
DURABLE_BACKENDS = ("s3", "gcs", "azure", "swift")


def _seconds(value):
    """Tempo durations look like `168h0m0s`. Returns None if unreadable."""
    if value is None:
        return None
    text = str(value).strip()
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    total, number = 0, ""
    for character in text:
        if character.isdigit():
            number += character
        elif character in units:
            if not number:
                return None
            total += int(number) * units[character]
            number = ""
        else:
            return None
    return total + (int(number) if number else 0)


@rule("TEMPO001", "reliability", "Traces are stored somewhere durable",
      backends=TEMPO, needs=CONFIG)
def durable_storage(snapshot):
    """`backend: local` keeps blocks on the container's own disk.

    It is what every quickstart uses and what a surprising number of
    deployments keep. Losing the node loses the traces, and Tempo cannot be
    scaled horizontally over it because the other replicas cannot see the
    blocks.
    """
    backend = _setting(snapshot, "storage.trace.backend")
    if backend in DURABLE_BACKENDS:
        return
    yield Finding(
        rule_id="TEMPO001", category="reliability",
        severity=Severity.WARNING,
        title="Traces are on local disk",
        evidence=f"storage.trace.backend = {backend}",
        impact="Losing the node loses every trace it holds, and Tempo cannot "
               "be run with more than one queryable replica because the "
               "others cannot see the blocks.",
        remediation="Point storage.trace.backend at object storage (s3, gcs, "
                    "azure). Local is correct for a laptop and for nothing "
                    "else.",
        targets=[snapshot.source_name], docs_url=DOCS)


@rule("TEMPO002", "retention", "Block retention is set", backends=TEMPO,
      needs=CONFIG)
def retention_is_set(snapshot):
    """Zero means the compactor never deletes a block."""
    value = _setting(snapshot, "compactor.compaction.block_retention")
    seconds = _seconds(value)
    if seconds is None:
        raise NotEvaluated(f"compactor.compaction.block_retention = {value!r} "
                           f"is not a duration this rule can read")
    if seconds > 0:
        return
    yield Finding(
        rule_id="TEMPO002", category="retention",
        severity=Severity.WARNING,
        title="Tempo keeps traces forever",
        evidence=f"compactor.compaction.block_retention = {value}",
        impact="Object storage grows without bound, and the bill arrives "
               "before anything looks broken.",
        remediation="Set compactor.compaction.block_retention to how long "
                    "traces are actually useful — typically days, not months.",
        targets=[snapshot.source_name], docs_url=DOCS)


@rule("TEMPO003", "observability", "The metrics generator is running",
      backends=TEMPO, needs=CONFIG)
def metrics_generator(snapshot):
    """Without it there is no service graph and no span metrics.

    Worth saying because people expect Tempo to have them: the processors are
    configured by default, and the whole feature still does nothing until a
    `remote_write` target exists to send the metrics to. Configured-looking
    and inert.
    """
    processors = _setting(snapshot, "metrics_generator.processor")
    remote_write = (snapshot.setting("metrics_generator.storage.remote_write")
                    or [])
    if remote_write:
        return
    yield Finding(
        rule_id="TEMPO003", category="observability",
        severity=Severity.INFO,
        title="The metrics generator has nowhere to write",
        evidence="metrics_generator.storage.remote_write is empty, so the "
                 f"configured processors ({', '.join(processors) if isinstance(processors, (list, dict)) else processors}) "
                 f"produce nothing",
        impact="No service graph and no span metrics. WDash does not read "
               "them, so nothing here breaks — but the per-service volume it "
               "cannot show comes from exactly this.",
        remediation="Point metrics_generator.storage.remote_write at a "
                    "Prometheus-compatible endpoint, or leave the processors "
                    "off so the configuration says what it does.",
        targets=[snapshot.source_name], docs_url=DOCS)


@rule("TEMPO004", "capacity", "A single trace cannot exhaust an ingester",
      backends=TEMPO, needs=CONFIG)
def max_bytes_per_trace(snapshot):
    """Zero means unlimited, and one runaway trace can then take Tempo down.

    A retry loop that reuses one trace id produces a trace with millions of
    spans. Held whole in an ingester, it is an out-of-memory kill rather than
    a rejected write.
    """
    value = _setting(snapshot, "overrides.defaults.global.max_bytes_per_trace")
    if int(value) > 0:
        return
    yield Finding(
        rule_id="TEMPO004", category="capacity",
        severity=Severity.WARNING,
        title="A single trace has no size limit",
        evidence="overrides.defaults.global.max_bytes_per_trace = 0 "
                 "(unlimited)",
        impact="A retry loop that reuses one trace id builds a trace with "
               "millions of spans. It is held whole in an ingester, so the "
               "failure is an out-of-memory kill rather than a rejected "
               "write.",
        remediation="Set overrides.defaults.global.max_bytes_per_trace (5 MB "
                    "is Tempo's own default). An oversized trace is then "
                    "refused and reported instead of taking the ingester "
                    "with it.",
        targets=[snapshot.source_name], docs_url=DOCS)


@rule("TEMPO005", "security", "Multi-tenancy is on", backends=TEMPO, needs=CONFIG)
def multitenancy(snapshot):
    """Same shape as Loki's: one tenant for everybody.

    And written the same way, with omitempty: false is not in
    /status/config at all. The lab's Tempo has no such key and answers a
    search with no tenant; read as "not off", this passed there.
    """
    if snapshot.setting("multitenancy_enabled", False):
        return
    yield Finding(
        rule_id="TEMPO005", category="security",
        severity=Severity.INFO,
        title="Tempo is running without tenants",
        evidence="multitenancy_enabled = false",
        impact="Every producer and reader shares one tenant, and every "
               "per-tenant limit is really an installation-wide limit.",
        remediation="Set multitenancy_enabled: true and give each team an "
                    "X-Scope-OrgID, if more than one team writes here.",
        targets=[snapshot.source_name], docs_url=DOCS)
