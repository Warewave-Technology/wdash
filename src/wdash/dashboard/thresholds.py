"""
When a dashboard should look alarming.

Deliberately not an alerting system. There is no notification, no schedule, no
silencing and no history — those are a different product, and building them
badly is worse than not having them. This answers one question: looking at this
dashboard right now, is anything outside what the owner considers normal?

That is worth having on its own. A number without a threshold makes every
reader re-derive "is 1,700 errors bad here?" from memory, and they will
disagree with each other.

Two metrics, chosen because they are the two the summary already computes:

    error_rate   share of records at ERROR or FATAL   (0.0 - 1.0)
    error_count  absolute number of them

Both are optional. A dashboard with neither is simply never alarming.
"""

METRICS = {
    "error_rate": {
        "label": "Error rate",
        "unit": "ratio",
        "description": "Share of records at ERROR or FATAL.",
    },
    "error_count": {
        "label": "Error count",
        "unit": "count",
        "description": "Absolute number of ERROR or FATAL records.",
    },
}

LEVELS = ("warning", "critical")


class ThresholdError(ValueError):
    """A threshold definition that cannot be evaluated."""


def normalise(thresholds):
    """Validate a threshold map. Returns {} for "none set".

    Shape: {"error_rate": {"warning": 0.02, "critical": 0.05}}
    """
    if not thresholds:
        return {}
    if not isinstance(thresholds, dict):
        raise ThresholdError("Thresholds must be an object.")

    out = {}
    for metric, levels in thresholds.items():
        if metric not in METRICS:
            raise ThresholdError(
                f"Unknown metric '{metric}'. Available: {', '.join(METRICS)}")
        if not isinstance(levels, dict):
            raise ThresholdError(f"'{metric}': expected warning/critical values.")

        parsed = {}
        for level in LEVELS:
            raw = levels.get(level)
            if raw is None or raw == "":
                continue
            try:
                value = float(raw)
            except (TypeError, ValueError):
                raise ThresholdError(f"'{metric}' {level}: not a number.")
            if value < 0:
                raise ThresholdError(f"'{metric}' {level}: must not be negative.")
            if METRICS[metric]["unit"] == "ratio" and value > 1:
                raise ThresholdError(
                    f"'{metric}' {level}: a rate is between 0 and 1 "
                    f"(use 0.05 for 5%).")
            parsed[level] = value

        # A critical below its warning can never be the reported level, because
        # critical is checked first — it would look set and do nothing.
        if ("warning" in parsed and "critical" in parsed
                and parsed["critical"] < parsed["warning"]):
            raise ThresholdError(
                f"'{metric}': critical must not be below warning.")

        if parsed:
            out[metric] = parsed
    return out


def evaluate(thresholds, values):
    """Compare current values against the thresholds.

    Returns None when nothing is configured — distinct from "ok", which is a
    claim that someone defined normal and this is inside it.
    """
    thresholds = thresholds or {}
    if not thresholds:
        return None

    breaches = []
    for metric, levels in thresholds.items():
        current = values.get(metric)
        if current is None:
            continue
        # Critical first: a value over both is critical, not warning.
        for level in reversed(LEVELS):
            limit = levels.get(level)
            if limit is not None and current >= limit:
                breaches.append({
                    "metric": metric,
                    "label": METRICS[metric]["label"],
                    "level": level,
                    "value": current,
                    "limit": limit,
                    "text": _describe(metric, current, limit, level),
                })
                break

    level = "ok"
    if any(b["level"] == "critical" for b in breaches):
        level = "critical"
    elif breaches:
        level = "warning"

    return {"level": level, "breaches": breaches}


def _describe(metric, value, limit, level):
    if METRICS[metric]["unit"] == "ratio":
        return (f"{METRICS[metric]['label']} {value * 100:.2f}% is over the "
                f"{level} threshold of {limit * 100:.2f}%")
    return (f"{METRICS[metric]['label']} {value:,.0f} is over the "
            f"{level} threshold of {limit:,.0f}")
