"""Index settings rules."""

from ..models import Finding, Severity, rule
from ._util import GB, human_bytes

CATEGORY = "indices"

LARGE_INDEX = 1 * GB
COMPRESSION_WORTH_IT = 10 * GB

#: Which indices there are and their settings, and how big each one is. An
#: index whose size was not collected reads as 0 bytes.
SIZED = ("index_settings", "indices_stats")


@rule(id="IDX001", category=CATEGORY, title="Refresh interval", needs=SIZED)
def refresh_interval(snap):
    large, small = [], []

    for index in snap.user_indices():
        interval = snap.index_setting(index, "index.refresh_interval")
        # When unset, the Elasticsearch default is one second
        if interval not in (None, "1s"):
            continue
        size = snap.index_size_bytes(index)
        (large if size >= LARGE_INDEX else small).append((index, interval, size))

    common_impact = (
        "Every refresh creates a new Lucene segment. One segment per second means "
        "constant merge pressure, wasting CPU and disk I/O. Log data does not need "
        "sub-second visibility.")
    common_fix = ('PUT /<index>/_settings {"index.refresh_interval": "30s"} — and put the '
                  "same value in the index template so new indices inherit it.")

    if large:
        yield Finding(
            rule_id="IDX001", category=CATEGORY, severity=Severity.WARNING,
            title="Large index is using the default refresh interval",
            evidence="; ".join(
                f"{idx}: {iv or 'unset (default 1s)'}, {human_bytes(size)}"
                for idx, iv, size in large[:8]),
            impact=common_impact,
            remediation=common_fix,
            targets=[idx for idx, _, _ in large],
        )

    if small:
        yield Finding(
            rule_id="IDX001", category=CATEGORY, severity=Severity.INFO,
            title="Index is using the default refresh interval",
            evidence="; ".join(f"{idx}: {iv or 'unset (default 1s)'}"
                               for idx, iv, _ in small[:10])
                     + (f" (+{len(small) - 10} more)" if len(small) > 10 else ""),
            impact=common_impact + " These indices are still small; the cost grows with them.",
            remediation=common_fix,
            targets=[idx for idx, _, _ in small],
        )


@rule(id="IDX002", category=CATEGORY, title="Lifecycle policy",
      distributions=("elasticsearch",),
      # `info` because whether it applies depends on the distribution, and
      # unread that defaults to Elasticsearch.
      needs=("info", "index_settings"))
def no_ilm_policy(snap):
    unmanaged = [index for index in snap.user_indices()
                 if not snap.index_setting(index, "index.lifecycle.name")]
    if not unmanaged:
        return

    yield Finding(
        rule_id="IDX002", category=CATEGORY, severity=Severity.WARNING,
        title="Indices have no lifecycle policy attached",
        evidence=f"{len(unmanaged)} indices without ILM: " + ", ".join(unmanaged[:10])
                 + (f" (+{len(unmanaged) - 10} more)" if len(unmanaged) > 10 else ""),
        impact=("Without ILM, indices grow without bound. In a logging system that means "
                "the disk fills and writes stop, sooner or later. Old data also stays on "
                "hot hardware, which is expensive and unnecessary."),
        remediation=("Define an ILM policy with rollover and retention and attach it to the "
                     "index template. A typical logging policy: roll over at 50GB or one "
                     "day, move to warm after 7 days, delete after 30. Data streams make "
                     "this simpler still."),
        targets=unmanaged,
    )


@rule(id="IDX003", category=CATEGORY, title="Index sorting",
      needs=("index_settings", "index_mappings"))
def index_sorting(snap):
    unsorted_indices = []
    for index in snap.user_indices():
        if snap.index_setting(index, "index.sort.field"):
            continue
        # Only meaningful for time-based indices
        if not snap.index_properties(index).get("@timestamp"):
            continue
        unsorted_indices.append(index)

    if not unsorted_indices:
        return

    yield Finding(
        rule_id="IDX003", category=CATEGORY, severity=Severity.INFO,
        title="Time-based index has no index sorting configured",
        evidence=", ".join(unsorted_indices[:10])
                 + (f" (+{len(unsorted_indices) - 10} more)" if len(unsorted_indices) > 10 else ""),
        impact=("WDash's most frequent query is 'the first N records by @timestamp "
                "descending'. With index sorting, Lucene can stop scanning a segment once "
                "it has enough results; without it, every segment is scanned end to end."),
        remediation=('Set {"index.sort.field": "@timestamp", "index.sort.order": "desc"} at '
                     "index creation. It cannot be changed on existing indices, so add it "
                     "to the template and gain on new ones. The trade-off is slightly "
                     "slower ingestion."),
        targets=unsorted_indices,
    )


@rule(id="IDX004", category=CATEGORY, title="Compression codec", needs=SIZED)
def compression_codec(snap):
    candidates = []
    for index in snap.user_indices():
        size = snap.index_size_bytes(index)
        if size < COMPRESSION_WORTH_IT:
            continue
        if snap.index_setting(index, "index.codec") == "best_compression":
            continue
        candidates.append((index, size))

    if not candidates:
        return

    yield Finding(
        rule_id="IDX004", category=CATEGORY, severity=Severity.INFO,
        title="Large index is stored with the default compression",
        evidence="; ".join(f"{idx}: {human_bytes(size)}" for idx, size in candidates[:8]),
        impact="best_compression uses DEFLATE instead of the default LZ4 and typically "
               "saves 15-25% of disk on log data.",
        remediation=('For indices that are no longer written to: {"index.codec": '
                     '"best_compression"} followed by a _forcemerge. The cost is higher '
                     "CPU and slightly increased read latency; not recommended for hot "
                     "indices."),
        targets=[idx for idx, _ in candidates],
    )


@rule(id="IDX005", category=CATEGORY, title="Slow query log", needs=("index_settings",))
def slowlog_not_configured(snap):
    indices = snap.user_indices()
    if not indices:
        return

    configured = [
        index for index in indices
        if any(snap.index_setting(index, key) for key in (
            "index.search.slowlog.threshold.query.warn",
            "index.search.slowlog.threshold.query.info",
            "index.search.slowlog.threshold.fetch.warn",
        ))
    ]
    if configured:
        return

    yield Finding(
        rule_id="IDX005", category=CATEGORY, severity=Severity.INFO,
        title="No index has a slow query log threshold",
        evidence=f"none of the {len(indices)} indices set a search slowlog threshold",
        impact="When a query gets slow there is no record of which query it was, on which "
               "shard, or how long it took. Diagnosis becomes guesswork.",
        remediation=('Add to the index template: '
                     '{"index.search.slowlog.threshold.query.warn": "5s", '
                     '"index.search.slowlog.threshold.query.info": "2s"}. '
                     "The overhead is negligible."),
        targets=[],
    )
