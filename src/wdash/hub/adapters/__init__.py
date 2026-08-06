"""Backend adapters. Everything backend-specific stays inside this package."""

from .elasticsearch import ElasticsearchLogSource, ElasticsearchTraceSource
from .es_trace_schema import ApmSpanSchema, OtelSpanSchema, SpanSchema, detect_schema

__all__ = [
    "LokiLogSource", "VictoriaLogsSource", "JaegerTraceSource", "TempoTraceSource",
    "ElasticsearchLogSource", "ElasticsearchTraceSource",
    "SpanSchema", "OtelSpanSchema", "ApmSpanSchema", "detect_schema",
]

from .loki import LokiLogSource  # noqa: E402
from .victorialogs import VictoriaLogsSource  # noqa: E402
from .jaeger import JaegerTraceSource  # noqa: E402
from .tempo import TempoTraceSource  # noqa: E402
