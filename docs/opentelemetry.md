# OpenTelemetry

WDash reads OpenTelemetry data. It does not collect it, and that is a decision
rather than a gap.

## Why WDash is not a collector

WDash is a read-only query layer. It cannot lose telemetry, because it never
holds any. Accepting OTLP would put it in the data path, where being down means
losing data rather than losing a dashboard — a completely different reliability
class and a completely different on-call story.

The other reasons, briefly:

- **Shape.** The OpenTelemetry Collector is Go and built for ingest. Telemetry
  volume is orders of magnitude above UI request volume; running both in one
  Python process means one starves the other.
- **Backpressure is unforgiving.** Queue in memory and a downstream outage
  becomes an out-of-memory kill. Queue on disk and you have written a durable
  queue. Drop, and you have silent data loss.
- **An OTLP receiver is an inbound write endpoint.** Its authentication is not
  standardised the way a browser session's is.

So: point your applications at a collector, point the collector at storage, and
point WDash at the same storage.

## A supported collector configuration

`lab/otel/collector.yaml` is a working file, not an illustration — the lab runs
it. The parts that matter:

```yaml
exporters:
  elasticsearch:
    endpoints: ["http://elasticsearch:9200"]
    mapping:
      mode: otel          # or ecs — WDash reads both
    logs_index: otel-logs-000001
    traces_index: otel-traces-000001

processors:
  memory_limiter:         # bound what a burst can consume
    limit_mib: 256
  batch:
    timeout: 2s
```

`mapping.mode` decides which shape lands, and WDash reads either:

| mode | Written as | WDash reads it with |
|---|---|---|
| `otel` | OpenTelemetry's own field names | `OtelLogSchema`, `OtelSpanSchema` |
| `ecs` | Elastic Common Schema | `FlatLogSchema`, `ApmSpanSchema` |

Tell WDash which indices hold traces so log searches do not scan them: on
the source's card under **Configuration → Sources**, the traces signal's
index patterns (`*traces*` and `*apm*` by default) and the logs signal's
exclude patterns. A source that serves both signals is one row, so the two
lists sit side by side.

## Running it in the lab

```bash
cd lab
./lab.sh up otel                       # collector on 4317 (gRPC) and 4318 (HTTP)
python otel/emit.py --traces 25        # push real OTLP through it
```

`emit.py` is not a seeder. The seeder writes documents straight into
Elasticsearch; this sends OTLP over the wire and lets the collector decide what
lands. The difference is the whole point.

## What running a real collector caught

The trace schema and the seeder had been written from the same assumption, so
they agreed with each other — and with nothing the ecosystem produces. Measured
against a real collector, before the fix:

| | WDash expected | Collector writes |
|---|---|---|
| log body | `message` | `body_text` |
| log severity | `level` | `severity_text` + `severity_number` |
| service | `service` | `resource.attributes.service.name` |
| span duration | `duration_ns` | `duration` |
| span kind | `SPAN_KIND_CLIENT` | `Client` |
| span status | `status_code: "OK"` | `status.code: "Ok"` |

The result was not an error. Logs came back with an empty body, an unknown
severity and no service; spans came back with no service, a duration of zero
and no status. Records that look like data.

A zero duration makes a waterfall meaningless, and an empty service breaks the
scope's service filter — which is an access boundary. It fails closed, so it
was not a vulnerability, but a restricted role would have seen nothing at all
and had no way to tell why.

Both shapes are read now, and `tests/test_otel_shapes.py` holds documents
captured from a real collector so the fixtures cannot drift back into agreeing
only with themselves.

A second pass (collector 0.109, `emit.py`'s own payload plus the cases
applications actually send) found three more things the collector does, and
`tests/test_es_logs.py` holds those documents:

| An application sends | The collector writes |
|---|---|
| a map as the body | `body_structured`, and no `body_text` |
| no severity text | no `severity_text` at all |
| no severity number | `severity_number: 0` |

The log list asked Elasticsearch only for the fields it shows, so a list row
never saw `severity_number` or `body_structured`: 5 of 11 records read
UNSPECIFIED in the list and INFO or ERROR when opened, and a map body read as
empty in both. And the record view shows resource and attribute keys by their
own names — `deployment.environment`, `request_id` — which a filter now also
looks for under `resource.attributes.` and `attributes.`.

Without `logs_index` and `traces_index` the exporter writes to data streams
rather than to a named index. WDash lists a data stream by its name, grants
and searches it by that name, and shows which backing index holds a record in
the raw view.

The trace SEARCH was left behind. Its clauses for an entry span, a failure and
a duration still asked for `SPAN_KIND_SERVER`, `status_code` and `duration_ns`,
so on a collector-written index the trace list, errors-only, a minimum
duration and "slowest" were empty, and every service had 0 errors — measured
on the lab over 7 days, 0 rows and 0 errors in 13,537 spans where the APM copy
of the same traces gave 25 rows and 171 errors. Nothing failed. Those clauses
now live on the schema beside the reader (`entry_filter`, `error_filter`,
`duration_filter`, `slowest_first`), so a change to one is a change to both,
and they ask for the collector's spelling (`kind: Server`, `status.code:
Error`, `duration`) beside the older one.

A span index is also told apart from a log index. A collector writes
`trace_id` and `span_id` onto a log record made inside a span, so the ids
alone are not a span schema: `OtelSpanSchema` wants `kind` and a duration too,
and refuses an index with log fields. A configured Elasticsearch trace source
whose patterns are left blank reads `*traces*` and `*apm*`, not `*`.

## If you do want ingest one day

Build it as a separate process (`wdash-ingest`) that shares the schema
definitions but not the Flask application. The UI can then never be starved by
ingest, and the two scale and restart independently. The one argument that
genuinely favours owning the write path is enrichment: WDash enforces RBAC in
the application because Elasticsearch's Basic licence has no document-level
security, and controlling ingest would let a tenant label be written reliably
rather than inferred.

That is a real benefit and a real cost. It is not a reason to accept OTLP
inside the web application.
