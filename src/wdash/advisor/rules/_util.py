"""Shared helpers for rule functions."""

import re

GB = 1024 ** 3
MB = 1024 ** 2

#: Elasticsearch's byte units, which are binary: 1gb is 1024**3.
_BYTE_UNITS = {"b": 1, "k": 1024, "kb": 1024, "m": MB, "mb": MB, "g": GB, "gb": GB,
               "t": 1024 * GB, "tb": 1024 * GB, "p": 1024 ** 2 * GB, "pb": 1024 ** 2 * GB}
_BYTE_SIZE = re.compile(r"(\d+(?:\.\d+)?)\s*(pb|tb|gb|mb|kb|[ptgmkb])")


def parse_bytes(value):
    """'100gb' -> bytes, the way Elasticsearch reads a byte size. None when
    the value is not one."""
    if value is None:
        return None
    match = _BYTE_SIZE.fullmatch(str(value).strip().lower())
    if not match:
        return None
    return int(float(match.group(1)) * _BYTE_UNITS[match.group(2)])


def parse_watermark(value):
    """A disk watermark, the way Elasticsearch reads one.

    ('ratio', 0.85) for '85%' or '0.85' — the share of the disk that may be
    USED — and ('bytes', n) for '100gb', the space that must stay FREE.
    None when it is neither, which a rule has to report rather than replace
    with a default.
    """
    if value is None:
        return None
    text = str(value).strip().lower()
    # Elasticsearch tries a ratio first unless the value ends in 'b'.
    if not text.endswith("b"):
        try:
            if text.endswith("%"):
                percent = float(text[:-1])
                if 0 <= percent <= 100:
                    return "ratio", percent / 100
            else:
                ratio = float(text)
                if ratio == 0:
                    return "bytes", 0
                if 0 < ratio <= 1:
                    return "ratio", ratio
        except ValueError:
            pass
    size = parse_bytes(text)
    return ("bytes", size) if size is not None else None


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
