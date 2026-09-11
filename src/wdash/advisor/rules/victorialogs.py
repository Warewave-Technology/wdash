"""
VictoriaLogs checks.

`/flags` reports only the flags that were SET, not every flag with its
default. That shape is what these rules are mostly about: an absent flag means
"left at the packaged default", and for retention and disk usage the default
is the thing worth knowing.

Which is also why they need `/flags` to have answered: absence is the
finding, and a page that could not be read is nothing but absence. They
reported "no authentication" from a server that had just answered 401.
"""

from ..models import Finding, NotEvaluated, Severity, rule

VL = ("victorialogs",)
DOCS = "https://docs.victoriametrics.com/victorialogs/"
FLAGS = ("flags",)

#: What VictoriaLogs uses when `-retentionPeriod` is not given.
DEFAULT_RETENTION = "7d"


def _days(value):
    """A VictoriaLogs retention value in days, or None if unreadable."""
    if value is None:
        return None
    text = str(value).strip().lower()
    units = {"d": 1, "w": 7, "y": 365, "m": 30}
    number = "".join(c for c in text if c.isdigit())
    if not number:
        return None
    unit = text[len(number):] or "m"      # bare numbers are months here
    return int(number) * units.get(unit, 0) or None


@rule("VL001", "retention", "Retention is chosen rather than inherited",
      backends=VL, needs=FLAGS)
def retention_is_explicit(snapshot):
    """The default is one month, and it is silent.

    `-retentionPeriod` absent means VictoriaLogs keeps a month. That is a
    reasonable default and a poor decision: somebody looking for last
    quarter's incident finds nothing and concludes the logs were never
    written.
    """
    if "retentionPeriod" in snapshot.settings:
        return
    yield Finding(
        rule_id="VL001", category="retention",
        severity=Severity.INFO,
        title="Retention is at the packaged default",
        evidence="-retentionPeriod is not set, so the default applies",
        impact="Logs older than the default are deleted without anything "
               "saying so. Somebody looking for an old incident finds an "
               "empty result and reads it as 'this was never logged'.",
        remediation="Pass -retentionPeriod explicitly, even if the value "
                    "matches the default. A stated retention is a decision; "
                    "an inherited one is a surprise.",
        targets=[snapshot.source_name], docs_url=DOCS)


@rule("VL002", "capacity", "Disk usage is bounded", backends=VL, needs=FLAGS)
def disk_usage_is_bounded(snapshot):
    """Without `-storage.maxDiskSpaceUsageBytes`, VictoriaLogs will use the
    whole volume and stop when it is full.

    Retention deletes by AGE. A volume can fill well before the oldest data is
    old enough to go, and the failure is ingestion stopping rather than
    anything being reported as unhealthy.
    """
    if "storage.maxDiskSpaceUsageBytes" in snapshot.settings:
        return
    free = snapshot.facts.get("vl_free_disk_space_bytes")
    evidence = "-storage.maxDiskSpaceUsageBytes is not set"
    if isinstance(free, (int, float)):
        evidence += f"; {free / 1e9:.1f} GB free right now"
    yield Finding(
        rule_id="VL002", category="capacity",
        severity=Severity.WARNING,
        title="Disk usage has no ceiling",
        evidence=evidence,
        impact="Retention deletes by age, so a volume can fill long before "
               "anything is old enough to remove. When it does, ingestion "
               "stops — the logs about the incident are the ones lost.",
        remediation="Set -storage.maxDiskSpaceUsageBytes below the volume "
                    "size. VictoriaLogs then drops the oldest data to stay "
                    "under it, which is a bounded loss rather than an outage.",
        targets=[snapshot.source_name], docs_url=DOCS)


@rule("VL003", "capacity", "Free disk space is healthy", backends=VL,
      needs=("metrics",))
def free_disk_space(snapshot):
    """Below a few gigabytes, VictoriaLogs stops accepting writes."""
    free = snapshot.facts.get("vl_free_disk_space_bytes")
    if not isinstance(free, (int, float)):
        raise NotEvaluated("/metrics has no vl_free_disk_space_bytes")
    gigabytes = free / 1e9
    if gigabytes >= 10:
        return
    severity = Severity.CRITICAL if gigabytes < 2 else Severity.WARNING
    yield Finding(
        rule_id="VL003", category="capacity",
        severity=severity,
        title="The storage volume is nearly full",
        evidence=f"vl_free_disk_space_bytes = {free:,.0f} "
                 f"({gigabytes:.1f} GB free)",
        impact="VictoriaLogs stops accepting writes when the volume fills. "
               "Nothing upstream is told, so the loss looks like a quiet "
               "period.",
        remediation="Grow the volume, lower -retentionPeriod, or set "
                    "-storage.maxDiskSpaceUsageBytes so the oldest data is "
                    "dropped instead of writes failing.",
        targets=[snapshot.source_name], docs_url=DOCS)


@rule("VL004", "security", "Read and write paths are protected", backends=VL,
      needs=FLAGS)
def authentication(snapshot):
    """VictoriaLogs has no built-in authentication.

    `-httpAuth.username` is the whole of it. Without it, anything that can
    reach the port can read every log and delete data through the admin API.
    """
    if "httpAuth.username" in snapshot.settings:
        return
    listen = snapshot.settings.get("httpListenAddr", "")
    # Bound to a loopback address, the exposure is the host rather than the
    # network, which is a different conversation.
    loopback = listen.startswith("127.") or listen.startswith("localhost")
    yield Finding(
        rule_id="VL004", category="security",
        severity=Severity.INFO if loopback else Severity.WARNING,
        title="VictoriaLogs has no authentication",
        evidence=f"-httpAuth.username is not set; listening on "
                 f"{listen or 'the default address'}",
        impact="Anything that can reach the port can read every log line. "
               "The delete API is on the same port.",
        remediation="Set -httpAuth.username and -httpAuth.password, or put it "
                    "behind a proxy that authenticates. WDash's own boundary "
                    "protects WDash's users, not the port.",
        targets=[snapshot.source_name], docs_url=DOCS)
