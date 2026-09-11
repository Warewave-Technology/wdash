"""
Loki checks.

Small on purpose. Loki's `/config` returns several hundred settings and most
of them are not worth an opinion — a rule for every knob produces a report
nobody reads, which is the same outcome as no report.

What is here is the handful that costs a deployment real money or real data:
retention that never deletes, a compactor that is not deleting anything, and
limits low enough to drop logs during the incident you are trying to read
about.
"""

from ..models import Finding, NotEvaluated, Severity, rule

LOKI = ("loki",)
DOCS = "https://grafana.com/docs/loki/latest/operations/storage/retention/"
#: Every rule here reads `/config`.
CONFIG = ("config",)


def _setting(snapshot, path):
    """A setting from `/config`, which lists the whole effective
    configuration — so one that is not there could not be read, and the
    rule has no verdict. It used to pass."""
    value = snapshot.setting(path)
    if value is None:
        raise NotEvaluated(f"{path} is not in /config")
    return value


def _duration_seconds(value):
    """Loki durations: `0s`, `744h`, `30d1h`, `1w`. Returns None if unreadable.

    None matters: a rule that cannot parse a value must skip rather than
    treat it as zero, or an unrecognised format turns into a finding about a
    setting that is perfectly fine.
    """
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800, "y": 31536000}
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
    if number:            # a bare number means seconds
        total += int(number)
    return total


@rule("LOKI001", "retention", "Retention is configured", backends=LOKI,
      needs=CONFIG)
def retention_is_set(snapshot):
    """`retention_period: 0s` means Loki never deletes anything.

    It is the default, and it is the setting that quietly turns into a storage
    bill and then into an outage when the volume fills. Nothing warns about
    it, because from Loki's point of view it is working perfectly.
    """
    value = _setting(snapshot, "limits_config.retention_period")
    seconds = _duration_seconds(value)
    if seconds is None:
        raise NotEvaluated(f"limits_config.retention_period = {value!r} is not "
                           f"a duration this rule can read")
    if seconds == 0:
        yield Finding(
            rule_id="LOKI001", category="retention",
            severity=Severity.WARNING,
            title="Loki keeps logs forever",
            evidence=f"limits_config.retention_period = {value}",
            impact="Storage grows without bound. Nothing reports this as a "
                   "problem until the volume is full, at which point ingestion "
                   "stops.",
            remediation="Set limits_config.retention_period to how long logs "
                        "are actually needed (for example 744h for a month), "
                        "and enable the compactor's retention — the setting on "
                        "its own deletes nothing.",
            targets=[snapshot.source_name], docs_url=DOCS)


@rule("LOKI002", "retention", "The compactor applies retention", backends=LOKI,
      needs=CONFIG)
def compactor_retention_enabled(snapshot):
    """A retention period with `retention_enabled: false` deletes nothing.

    Two settings, and the one people set is not the one that does the work.
    The result looks configured and behaves exactly like no retention at all.
    """
    enabled = _setting(snapshot, "compactor.retention_enabled")
    if enabled:
        return
    period = _duration_seconds(
        _setting(snapshot, "limits_config.retention_period"))
    if period is None:
        raise NotEvaluated("limits_config.retention_period is not a duration "
                           "this rule can read")
    if period:
        yield Finding(
            rule_id="LOKI002", category="retention",
            severity=Severity.CRITICAL,
            title="Retention is set but nothing enforces it",
            evidence=f"limits_config.retention_period = "
                     f"{snapshot.setting('limits_config.retention_period')}, "
                     f"compactor.retention_enabled = false",
            impact="Logs are never deleted. The configuration says otherwise, "
                   "so this is usually found when the disk fills.",
            remediation="Set compactor.retention_enabled: true and make sure "
                        "the compactor is running. Retention is applied by the "
                        "compactor, not by the limit.",
            targets=[snapshot.source_name], docs_url=DOCS)


@rule("LOKI003", "ingestion", "Old samples are rejected", backends=LOKI,
      needs=CONFIG)
def rejects_old_samples(snapshot):
    """Accepting arbitrarily old lines corrupts every time-based query.

    A backfill or a clock-skewed host writes into the past, and the histogram
    somebody is reading gains volume that was not there a moment ago.
    """
    if _setting(snapshot, "limits_config.reject_old_samples"):
        return
    yield Finding(
        rule_id="LOKI003", category="ingestion",
        severity=Severity.WARNING,
        title="Loki accepts arbitrarily old log lines",
        evidence="limits_config.reject_old_samples = false",
        impact="A backfill or a host with a wrong clock writes into the past. "
               "Time-based queries then return different answers for a window "
               "that has already been looked at.",
        remediation="Set limits_config.reject_old_samples: true and "
                    "reject_old_samples_max_age to a window that matches how "
                    "far behind a legitimate producer can be.",
        targets=[snapshot.source_name], docs_url=DOCS)


@rule("LOKI004", "capacity", "The ingestion limit is not at its default",
      backends=LOKI, needs=CONFIG)
def ingestion_rate_is_considered(snapshot):
    """4 MB/s per tenant is the packaged default, not a decision.

    It is also the number that drops logs during an incident, because an
    incident is when volume spikes — so the data you most want is the data
    most likely to be missing.
    """
    rate = _setting(snapshot, "limits_config.ingestion_rate_mb")
    if float(rate) != 4:
        return
    yield Finding(
        rule_id="LOKI004", category="capacity",
        severity=Severity.INFO,
        title="Ingestion rate is at the packaged default",
        evidence=f"limits_config.ingestion_rate_mb = {rate} (default), "
                 f"burst = "
                 f"{snapshot.setting('limits_config.ingestion_burst_size_mb')}",
        impact="Volume spikes during an incident, which is when the limit is "
               "hit and lines are dropped — so the logs least likely to be "
               "there are the ones being looked for.",
        remediation="Measure the steady-state rate and set "
                    "limits_config.ingestion_rate_mb above the peak, not the "
                    "average. Dropped lines appear as "
                    "`loki_discarded_samples_total`.",
        targets=[snapshot.source_name])


@rule("LOKI005", "reliability", "Data survives losing one ingester",
      backends=LOKI, needs=CONFIG)
def replication_factor(snapshot):
    """A replication factor of 1 means an ingester restart loses whatever it
    was holding that had not been flushed."""
    factor = _setting(snapshot, "common.replication_factor")
    if int(factor) > 1:
        return
    yield Finding(
        rule_id="LOKI005", category="reliability",
        severity=Severity.INFO,
        title="No replication between ingesters",
        evidence=f"common.replication_factor = {factor}",
        impact="An ingester that restarts before flushing loses the lines it "
               "was holding. On a single-binary deployment this is expected; "
               "on a distributed one it is data loss nobody is told about.",
        remediation="Set common.replication_factor to 3 for a distributed "
                    "deployment. Leave it at 1 for a single binary, where "
                    "there is nothing to replicate to.",
        targets=[snapshot.source_name])


@rule("LOKI006", "security", "Multi-tenancy is on", backends=LOKI, needs=CONFIG)
def auth_enabled(snapshot):
    """With `auth_enabled: false` every write and read lands in one tenant.

    WDash enforces its own boundary in front, so this is not a hole in WDash —
    but anything else pointed at the same Loki sees everything, and the
    per-tenant limits above apply to the whole installation at once.

    Loki writes this one with omitempty, so false is not in /config at all:
    absent means off. Read as "not off", it passed on the lab's Loki, which
    answers queries with no tenant.
    """
    if snapshot.setting("auth_enabled", False):
        return
    yield Finding(
        rule_id="LOKI006", category="security",
        severity=Severity.INFO,
        title="Loki is running without tenants",
        evidence="auth_enabled = false",
        impact="Every producer and every reader shares one tenant. WDash "
               "applies its own boundary, but anything else talking to this "
               "Loki sees all of it, and every per-tenant limit is really an "
               "installation-wide limit.",
        remediation="Set auth_enabled: true and give each team an "
                    "X-Scope-OrgID, if more than one team writes here.",
        targets=[snapshot.source_name])
