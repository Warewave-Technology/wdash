"""Shared helpers for rule functions."""

GB = 1024 ** 3
MB = 1024 ** 2


def parse_percent(value):
    """'85%' -> 85.0. Returns None when the value is not a percentage (e.g. '100gb')."""
    if value is None:
        return None
    text = str(value).strip()
    if not text.endswith("%"):
        return None
    try:
        return float(text[:-1])
    except ValueError:
        return None


def human_bytes(n):
    try:
        n = float(n)
    except (TypeError, ValueError):
        return "?"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024 or unit == "TB":
            return f"{n:.1f}{unit}" if unit != "B" else f"{int(n)}B"
        n /= 1024
    return f"{n:.1f}TB"


def count_fields(properties):
    """Total field count in a mapping.

    Approximates the way Elasticsearch counts total_fields: object fields count
    themselves, and multi-field sub-fields count too.
    """
    total = 0
    for _, definition in (properties or {}).items():
        if not isinstance(definition, dict):
            continue
        total += 1
        if "properties" in definition:
            total += count_fields(definition["properties"])
        else:
            total += len(definition.get("fields") or {})
    return total


def resolve_field(properties, dotted_name):
    """Resolve a dotted path such as 'error.stack_trace' inside a mapping."""
    current = properties or {}
    parts = dotted_name.split(".")
    for i, part in enumerate(parts):
        definition = current.get(part)
        if not isinstance(definition, dict):
            return None
        if i == len(parts) - 1:
            return definition
        current = definition.get("properties") or {}
    return None


def is_aggregatable(definition):
    """Can this field definition support a terms aggregation?

    Returns: (usable, needs_keyword_subfield)
      (True,  False) -> aggregates directly
      (True,  True)  -> only through the .keyword sub-field
      (False, False) -> cannot be aggregated
    """
    if not isinstance(definition, dict):
        return False, False
    field_type = definition.get("type")
    if field_type == "text":
        subfields = definition.get("fields") or {}
        has_keyword = any(sub.get("type") == "keyword" for sub in subfields.values())
        return (True, True) if has_keyword else (False, False)
    aggregatable = {"keyword", "boolean", "byte", "short", "integer", "long",
                    "float", "double", "half_float", "scaled_float", "date", "ip"}
    if field_type in aggregatable:
        return definition.get("doc_values", True) is not False, False
    return False, False


def sum_node_stat(snapshot, *path):
    """Sum a numeric statistic across every node."""
    total = 0
    for _, _, stats in snapshot.nodes():
        current = stats
        for key in path:
            current = (current or {}).get(key)
            if current is None:
                break
        if isinstance(current, (int, float)):
            total += current
    return total
