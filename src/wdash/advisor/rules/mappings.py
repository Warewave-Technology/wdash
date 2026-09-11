"""Mapping rules — these affect query correctness and performance directly."""

from ..models import Finding, Severity, rule
from ..snapshot import AGGREGATED_FIELDS, LARGE_TEXT_FIELDS
from ._util import count_fields, is_aggregatable, resolve_field

CATEGORY = "mappings"

DEFAULT_FIELD_LIMIT = 1000
# Below this count, dynamic mapping is ordinary usage rather than a risk
DYNAMIC_FIELD_THRESHOLD = 150

#: Which indices there are, and their mappings.
MAPPED = ("index_settings", "index_mappings")


@rule(id="MAP001", category=CATEGORY, title="Aggregated fields are aggregatable",
      needs=MAPPED)
def aggregation_fields_not_aggregatable(snap):
    """Check the mapping of every field WDash runs a terms aggregation on.

    This rule catches a real production failure: the dashboard endpoints
    aggregate on 'level' without a .keyword suffix. If the field is mapped as
    analysed text the query fails outright.
    """
    broken, needs_suffix = [], []

    for index in snap.user_indices():
        properties = snap.index_properties(index)
        if not properties:
            continue
        for field_name in AGGREGATED_FIELDS:
            definition = resolve_field(properties, field_name)
            if definition is None:
                continue  # field absent here — may not be a log index
            if "properties" in definition:
                # An object field (for example service.name/service.version in the
                # trace schema). Not a leaf, so aggregatability does not apply.
                continue
            ok, needs_keyword = is_aggregatable(definition)
            if not ok:
                broken.append((index, field_name, definition.get("type")))
            elif needs_keyword:
                needs_suffix.append((index, field_name))

    if broken:
        yield Finding(
            rule_id="MAP001", category=CATEGORY, severity=Severity.CRITICAL,
            title="An aggregated field cannot be aggregated",
            evidence="; ".join(f"{idx}.{fld} (type={typ})" for idx, fld, typ in broken[:10])
                     + (f" (+{len(broken) - 10} more)" if len(broken) > 10 else ""),
            impact=("WDash runs terms aggregations on these fields. Because the field is "
                    "analysed text with no .keyword sub-field, the query fails with "
                    "'Fielddata is disabled' and the dashboard panel renders empty."),
            remediation=("Map the field as keyword. Mappings cannot be changed in place: "
                         "define a new index template and reindex. Do not enable "
                         "fielddata as a shortcut — it loads the whole field into heap "
                         "and trips circuit breakers."),
            targets=sorted({idx for idx, _, _ in broken}),
        )

    if needs_suffix:
        yield Finding(
            rule_id="MAP001", category=CATEGORY, severity=Severity.WARNING,
            title="Aggregated field only works through .keyword",
            evidence="; ".join(f"{idx}.{fld} needs {fld}.keyword"
                               for idx, fld in needs_suffix[:10])
                     + (f" (+{len(needs_suffix) - 10} more)" if len(needs_suffix) > 10 else ""),
            impact=("The field is mapped as text with a .keyword sub-field, so "
                    "aggregations only work with the suffix. WDash is inconsistent about "
                    "this: some queries use 'service.keyword' and others plain 'level'."),
            remediation=("Use the .keyword suffix in queries, or map the field as keyword "
                         "directly and drop the text copy — a field used for aggregation "
                         "rarely needs full-text analysis."),
            targets=sorted({idx for idx, _ in needs_suffix}),
        )


@rule(id="MAP002", category=CATEGORY, title="Unbounded dynamic mapping", needs=MAPPED)
def dynamic_mapping_explosion(snap):
    offenders = []
    for index in snap.user_indices():
        root = snap.index_mapping_root(index)
        if not root:
            continue
        # When 'dynamic' is not stated, the Elasticsearch default is true
        dynamic = root.get("dynamic", True)
        if dynamic in (False, "false", "strict"):
            continue
        total = count_fields(root.get("properties"))
        if total >= DYNAMIC_FIELD_THRESHOLD:
            offenders.append((index, total, dynamic))

    if not offenders:
        return

    yield Finding(
        rule_id="MAP002", category=CATEGORY, severity=Severity.WARNING,
        title="Field count has grown under dynamic mapping",
        evidence="; ".join(f"{idx}: {n} fields (dynamic={d})" for idx, n, d in offenders[:8])
                 + (f" (+{len(offenders) - 8} more)" if len(offenders) > 8 else ""),
        impact=("Dynamic mapping turns every new JSON key into a permanent field. As "
                "applications log free-form structures the mapping keeps growing, which "
                "inflates cluster state, slows the master node, and eventually stops "
                "ingestion when the field limit is reached."),
        remediation=('Set "dynamic": "strict" or "false" in the index template and declare '
                     "the expected fields. If free-form data must be stored, use the "
                     "flattened field type — it holds arbitrary keys under a single "
                     "mapping entry."),
        targets=[idx for idx, _, _ in offenders],
    )


@rule(id="MAP003", category=CATEGORY, title="Field count limit", needs=MAPPED)
def field_limit(snap):
    warnings, criticals = [], []

    for index in snap.user_indices():
        properties = snap.index_properties(index)
        if not properties:
            continue
        total = count_fields(properties)
        try:
            limit = int(snap.index_setting(
                index, "index.mapping.total_fields.limit", DEFAULT_FIELD_LIMIT))
        except (TypeError, ValueError):
            limit = DEFAULT_FIELD_LIMIT

        usage = total / limit * 100
        if usage >= 80:
            criticals.append((index, total, limit, usage))
        elif usage >= 50:
            warnings.append((index, total, limit, usage))

    for bucket, severity in ((criticals, Severity.CRITICAL), (warnings, Severity.WARNING)):
        if not bucket:
            continue
        yield Finding(
            rule_id="MAP003", category=CATEGORY, severity=severity,
            title="Index is approaching its field limit",
            evidence="; ".join(f"{idx}: {n}/{lim} fields ({pct:.0f}%)"
                               for idx, n, lim, pct in bucket[:8])
                     + (f" (+{len(bucket) - 8} more)" if len(bucket) > 8 else ""),
            impact=("Once the limit is reached, documents containing new fields are "
                    "rejected and ingestion stops. Field count also inflates the size of "
                    "cluster state."),
            remediation=("Reduce the field count rather than raising the limit: remove "
                         "unused fields from the mapping, switch free-form data to the "
                         "flattened type, and constrain dynamic mapping (MAP002)."),
            targets=[idx for idx, _, _, _ in bucket],
        )


@rule(id="MAP004", category=CATEGORY, title="Redundant .keyword on a large text field",
      needs=MAPPED)
def redundant_keyword_subfield(snap):
    offenders = []
    for index in snap.user_indices():
        properties = snap.index_properties(index)
        if not properties:
            continue
        for field_name in LARGE_TEXT_FIELDS:
            definition = resolve_field(properties, field_name)
            if not isinstance(definition, dict) or definition.get("type") != "text":
                continue
            subfields = definition.get("fields") or {}
            if any(sub.get("type") == "keyword" for sub in subfields.values()):
                offenders.append((index, field_name))

    if not offenders:
        return

    yield Finding(
        rule_id="MAP004", category=CATEGORY, severity=Severity.WARNING,
        title="Large text field is indexed as both text and keyword",
        evidence="; ".join(f"{idx}.{fld}" for idx, fld in offenders[:10])
                 + (f" (+{len(offenders) - 10} more)" if len(offenders) > 10 else ""),
        impact=("Large free-text fields such as a log message are never aggregated or "
                "sorted on; the .keyword sub-field only consumes space. These fields are "
                "usually the largest part of the index, so the waste is large too. Values "
                "beyond ignore_above are not indexed anyway."),
        remediation=('Drop the sub-field in the index template: "message": {"type": "text"}. '
                     "The change applies to new indices; reindexing is required to reclaim "
                     "space in existing ones."),
        targets=sorted({idx for idx, _ in offenders}),
    )


@rule(id="MAP005", category=CATEGORY, title="Time field", needs=MAPPED)
def timestamp_field(snap):
    missing, alternative = [], []

    for index in snap.user_indices():
        properties = snap.index_properties(index)
        if not properties:
            continue
        if resolve_field(properties, "@timestamp"):
            continue
        date_fields = [name for name, defn in properties.items()
                       if isinstance(defn, dict) and defn.get("type") == "date"]
        if date_fields:
            alternative.append((index, date_fields[0]))
        else:
            missing.append(index)

    if missing:
        yield Finding(
            rule_id="MAP005", category=CATEGORY, severity=Severity.WARNING,
            title="Index has no date field",
            evidence=", ".join(missing[:10])
                     + (f" (+{len(missing) - 10} more)" if len(missing) > 10 else ""),
            impact="No time range filter can be applied. Because WDash requires a time "
                   "range on every search, these indices never return results.",
            remediation="Add an @timestamp field of type date for time-based data.",
            targets=missing,
        )

    if alternative:
        yield Finding(
            rule_id="MAP005", category=CATEGORY, severity=Severity.INFO,
            title="No @timestamp, but another date field exists",
            evidence="; ".join(f"{idx}: uses '{fld}'" for idx, fld in alternative[:10])
                     + (f" (+{len(alternative) - 10} more)" if len(alternative) > 10 else ""),
            impact="WDash queries assume a field named @timestamp. These indices will not "
                   "match the time filter.",
            remediation="Copy the field to @timestamp in an ingest pipeline, or define a "
                        "field alias from @timestamp to the existing date field.",
            targets=[idx for idx, _ in alternative],
        )
