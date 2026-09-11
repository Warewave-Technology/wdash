# The hub

The layer that brings multiple observability backends under one interface, one
authorization model and one internal representation.

## Three design decisions

### 1. The internal model belongs to no backend

Elasticsearch's `hits` / `_source` / `aggregations` shape does not leak into the
codebase. The internal model speaks **OpenTelemetry semantic conventions**: a
log message is `body`, its level is `severity`, service and host information
lives in `resource`.

The reason is direction of travel. OTel is where the industry is heading and it
is on our roadmap; Elastic donated ECS to OTel and the two schemas are actively
converging. The ECS-to-OTel conversion happens inside the adapter, on read.

The cost is a translation layer per adapter. The return is that adding a second
backend means writing an adapter rather than a rewrite.

### 2. Scope is a required argument

```python
def search(self, query, scope): ...
def trace(self, trace_id, window, scope): ...
```

Elasticsearch's Basic licence has **no document- or field-level security**. All
authorization therefore lives in the application, and WDash has to be the only
door to the cluster.

In a design like that, the most dangerous failure is someone forgetting to
filter. Making scope optional means "one day somebody forgets"; making it
required turns forgetting into a call error. We do not leave this to code
review.

Two further guards:

- `Scope.is_empty` — no query is issued with an empty scope. An empty index
  list sent to Elasticsearch means `*`, so a user with access to nothing would
  see everything. Adapters return early and a test locks that in.
- `Scope.resolve()` — adapters always derive the list of containers to query
  from this method.

The operational counterpart: Elasticsearch should only be reachable from WDash
at the network level. If the application layer is the only gate, it must not be
possible to walk around it. The Advisor's `SEC001` rule exists to remind you.

### 3. Capabilities are explicit

No backend does everything. A source declares what it supports through
`capabilities` and the UI does not offer features the backend cannot serve.
The hub makes differences visible rather than hiding them — hiding them means a
feature that silently misbehaves.

## Layout

```
hub/
├── scope.py           Scope — the authorization boundary
├── patterns.py        one pattern language, shared with the adapters
├── models.py          neutral model: LogRecord, LogPage, Span, Trace, Bucket
├── query.py           LogQuery, TraceQuery, TimeWindow (alignment included)
├── query_language.py  neutral query parser
├── aggregation.py     Terms, DateHistogram, Bucket
├── source.py          LogSource / TraceSource interfaces + Capability
├── fanout.py          every source behind one, for merged search
├── factory.py         stored source definitions -> live adapters
├── probe.py           "is this reachable?", for the configuration page
└── adapters/
    ├── elasticsearch.py      Elasticsearch -> neutral model
    ├── loki.py               Grafana Loki -> neutral model
    ├── es_log_schema.py      log shapes (OTel collector, flat)
    └── es_trace_schema.py    trace shapes (OTel, Elastic APM)
```

Schema knowledge lives only in the two `*_schema.py` files. Adding a third
shape means adding a class there; nothing else changes.

The log side got its schema layer late, and only because a real collector was
put in the lab: the reader had been written against a fixture that had itself
been written from an assumption, so the two agreed with each other and with
nothing the ecosystem produces. See
[opentelemetry.md](opentelemetry.md).

## Usage

```python
from wdash.hub import Hub, Scope, LogQuery, TimeWindow
from wdash.hub.adapters import ElasticsearchLogSource, ElasticsearchTraceSource

hub = Hub()
hub.add_logs(ElasticsearchLogSource(es))
hub.add_traces(ElasticsearchTraceSource(es))

scope = Scope.from_user(current_user)          # bridge from the existing RBAC
window = TimeWindow.of("24h")                  # aligned to cache-friendly bounds

page = hub.logs().search(
    LogQuery(window=window, text="severity:ERROR", limit=50), scope)

trace = hub.traces().trace("abc123", window, scope)
for span, depth in trace.waterfall():
    print("  " * depth, span.service, span.duration_us)
```

## Schema independence, verified

The claim the hub rests on is this: *the same logical trace resolves the same
way in the neutral model regardless of which schema stores it.* If that does
not hold, the abstraction is lying.

The lab carries the same traces in both the OTel and the Elastic APM schema:

```
trace_id: 28a0ab9b057647fe82f18eb98f63bb82
  from the OTel schema : 6 spans
  from the APM schema  : 6 spans
  identical in the neutral model: True

25 sampled traces: 25/25 resolved identically
```

This check is pinned in `tests/test_hub.py::LiveSchemaEquivalenceTest` and
skips when the lab is not running. If the schema logic breaks quietly, the test
catches it.

Worth recording: the check **failed** the first time it ran and exposed a real
defect in the lab seed — the two schemas were writing the same span with
different `name` and `kind` values (OTel called intermediate services
`INTERNAL`, APM called them `CLIENT`). The adapter was right and the fixture
was wrong. The seed was fixed.

## Time alignment

`TimeWindow` aligns its bounds through `utils.timerange`, so the same logical
query produces the same bounds whatever backend serves it and Elasticsearch's
request cache actually hits. Measured in the lab with twenty users opening the
same dashboard:

| | hits | misses |
|---|---|---|
| unaligned | 0 | 200 |
| aligned | 200 | 0 |

## Wire format

The neutral model is spoken on the wire too. Elasticsearch's shape now exists
only inside the adapter:

| | Before | Now |
|---|---|---|
| Record list | `hits[].{_source,_index,_id}` | `records[].{body,severity,resource,attributes,ref}` |
| Time | `@timestamp` | `timestamp` |
| Message | `message` | `body` |
| Level | `level` | `severity` (normalised) + `severity_text` (raw) |
| Pagination | `next_search_after` | `cursor` |
| Bucket | `{key_as_string, doc_count}` | `{key, key_text, count}` |
| Nested aggregation | `{buckets: [...]}` | `sub: {name: [...]}` |
| Index list | `indices` | `containers` |

A record handle is a token in `ref` (`backend:container:id`). The web client
takes the container and the id from it for the record, raw and context views —
`/api/log/<container>/<id>` — and sends the record's own `source` as
`?source=`, so the record is read from the source that listed it. It never
needs to know which backend that is. For a data stream the container is the
stream's name, not the backing index the record is stored in: that is what a
role is granted, and the raw view says which backing index holds it.

**A concrete payoff:** because a record carries `trace_id` as a contracted
field, the log detail view can link straight to a trace waterfall. That link
used to be a field buried in `_source` with no contract behind it.

### The one deliberate exception

`LogSource.raw(ref, scope)` returns the stored document in the backend's own
shape, and `/api/log/<container>/<id>/raw` serves it to the detail modal's
**Raw** tab.

This is not a leak the abstraction failed to catch — it is a declared
`Capability.RAW_DOCUMENT`, and a source that cannot serve it raises rather than
faking an empty answer. The reason it has to exist: `fetch` returns what WDash
*understood*, so when a field is missing from the record view the question is
always "did it never arrive, or did we fail to map it?". Only the stored
document answers that, and the alternative is a shell on the cluster.

The rules that keep it from becoming a back door:

- **Nothing in WDash branches on it.** It is display-only. The moment a feature
  reads a field out of it, that field belongs in the neutral model instead.
- **Same scope check as everything else.** It is an escape hatch from the
  *model*, never from the *index boundary* — tested explicitly.
- **Fetched only when the tab is opened.** It costs a second request.

The modal shows both, labelled, because they answer different questions: JSON
is the record as WDash understands it, Raw is what is actually stored.

## Query language

The syntax users type has NOT changed — people know `level:ERROR` and saved
searches keep working. What changed is the internal representation: the text is
parsed into a neutral tree in `hub/query_language.py` and each adapter renders
it into its own language.

```
"level:ERROR AND service:payment*"
    -> And(Term("severity","ERROR"), Prefix("service","payment"))
    -> {"bool": {"must": [{"match": {"level": ...}}, {"prefix": {"service": ...}}]}}
```

Field names are neutral in the tree; `level` -> `severity` and `message` ->
`body` are resolved at parse time. Users can type either form.

Two side benefits:

- **Raw text never reaches Elasticsearch.** What we emit is query DSL;
  `query_string` is not used anywhere. We decide which clauses land in filter
  context.
- **Syntax errors are caught before the query leaves the process**, with a
  position: `'level:' expects a value (position 0)`. Previously Elasticsearch's
  `parsing_exception` text was surfaced to the user.

A `Term` node renders to `match` rather than `term` — deliberately, because
`term` silently matches nothing on an analysed field.

## Migration status

| Area | Status |
|---|---|
| Trace endpoints | On the hub |
| Log endpoints | On the hub |
| Dashboard endpoints | On the hub |

`ElasticsearchClient` is now nothing but a connection factory (346 lines down
to under 40). All query logic lives in adapters, and there are three of them:
Elasticsearch for logs and traces, Loki for logs, and the fan-out that presents
every one of them as a single source.

The migration ran in two stages: first the backend moved to the hub with the
wire contract preserved, then the wire format itself moved to the neutral
model. Behaviour preservation in the first stage was verified by running the
old and new applications side by side and comparing responses.

The dashboard migration surfaced three real defects, all of which predated it:

| Finding | Previous behaviour |
|---|---|
| The services panel showed a single "unknown" bar | It queried `service.keyword`; with the field absent, `missing: "unknown"` swept up every document |
| Total record count was stuck at 10,000 | `track_total_hits` was never set, so Elasticsearch's default cap applied |
| A non-aggregatable field returned a 500 | Now an empty panel plus a reason |

### Panel fan-out

The dashboard UI used to call a separate endpoint per panel. The query was
identical in all of them; only the aggregations differed. It now makes a single
`/data` call:

| | HTTP requests | Elasticsearch queries | Time |
|---|---|---|---|
| Before | 5 | 5 | ~55ms |
| After | 1 | 1 | ~8ms |

Timeline interval also scales with the window now: 23 buckets over 24 hours
instead of 288. A fixed five-minute bucket produced roughly 2000 points over
seven days.

The per-panel endpoints remain for API compatibility and have tests; the UI
does not call them.

### Batching queries that cannot be merged

The previous-period comparison covers a different time window, so it cannot
share the main aggregation. It can share the round trip:

```python
results = logs.multi_aggregate([
    (query,          [timeline, log_levels, services, heatmap]),
    (baseline_query, [log_levels]),
], scope)
```

`multi_aggregate` renders every request into one `_msearch` and returns one
result per request, in order. A single request skips `_msearch` and uses a
plain search — batching one query buys nothing and costs a bigger payload.

The contract the tests hold is *round trips*, not queries: `/data` issues two
queries in one call. Counting queries would have made the correct
implementation look like a regression.

### `failed` is not `total == 0`

`AggregationResult.failed` says the query did not run. That is different from a
query that ran and matched nothing, and conflating the two is how a backend
hiccup renders as "traffic dropped to zero". `_msearch` reports per-sub-query
errors inside a **200** response, so this is easy to get wrong: one bad
sub-query must not lose the others, and must not pass as data either.

The dashboard omits `previous_period` entirely when the baseline failed, and
still shows it when the baseline genuinely had no logs.

## Trace search

`TraceSource.search()` finds traces by querying SPANS rather than aggregating
over trace ids. A terms aggregation on `trace_id` would be both expensive and
only approximately correct at high cardinality; one span per trace with
`collapse` doing the de-duplication is exact and cheap.

Which span represents a trace depends on the question:

| Query | Span shown | Why |
|---|---|---|
| Filtered by service | That service's entry span | The user asked about that service's work |
| Unfiltered | The trace root | A plain trace list should show where each request came in |
| Unfiltered, services narrowed | The root if visible, else the earliest visible entry span | The root may be a service the role cannot see |

Without the root restriction, `collapse` picks whichever span sorts first —
usually some downstream service, which reads as noise in a trace list. When the
role's services are narrowed the root cannot be required: every request enters
through the gateway, so a role that may not see it got no trace at all. Every
visible entry span competes instead, and `collapse.inner_hits` picks the one
that describes the trace.

The scope's service allowlist is pushed **into** the query rather than applied
afterwards. That is not an optimisation: `collapse` returns the top N by sort
order, so post-filtering leaves a restricted role with an empty page even when
matching traces exist. This was a real bug, caught by checking what the
`viewer` role actually saw.

## Adding a source

Every source must pass `tests/conformance.py`. Write the adapter against it
rather than auditing afterwards — that is the difference between adding a
backend being a day's work and being a security review.

```python
class MyLogConformanceTest(LogSourceConformance, unittest.TestCase):
    def build(self):
        harness = MyFakeBackend()
        return MyLogSource(harness, name="mine"), harness
```

The harness reports what the backend was actually asked, which is the only way
to check that a filter was pushed down rather than applied afterwards.

Every check exists because something broke:

| Check | What it caught |
|---|---|
| An empty scope issues no query | An empty index list means `*` to Elasticsearch — a user allowed nothing would have seen everything |
| The scope is pushed into the query | `collapse` had already picked its top N before a post-filter ran, so a restricted role saw a blank page and no error |
| Failure is not emptiness | A failed sub-query returning zero renders as "traffic has stopped" |
| Capabilities are honest | A missing feature returning empty looks like missing data |
| Records name their source | Two Elasticsearch sources both say "elasticsearch" |

Skipping a check is allowed through `SKIP`, and is a documented gap rather than
a silent pass.

### Loki, and where it differs

`LokiLogSource` is the second implementation, and the places it diverges are
the interesting ones:

- **`{}` is not valid LogQL.** Loki cannot express "everything", so a source
  must be told which label names a container (`stream_label`, usually
  `service_name`). The neutral `*` has no translation, and inventing a selector
  would quietly read more or less than was asked for.
- **Filtering is two-stage.** Label matchers are indexed; line filters scan.
  Pushing what we can into the selector is the difference between a query that
  returns and one that times out on a week of data — and it is where the scope
  is enforced, for the same reason it is pushed into the Elasticsearch query.
- **A query it cannot express is refused, not trimmed.** Dropping a clause
  returns MORE than was asked for, the one direction an access-controlled
  system must never round in. That holds for dashboard panels too: they count
  over the same pipeline a search runs, not over the bare streams.
- **A level is matched however it was written.** `level:ERROR` becomes a
  case-insensitive match on every spelling that normalises to ERROR (`error`,
  `err`), because that is how records and panels count it. VictoriaLogs does
  the same with an anchored regexp filter.
- **Fewer capabilities, declared honestly.** No `FIELD_STATS` (Loki has no
  field mappings), no `CONTEXT` or `RAW_DOCUMENT` (no document to fetch by id).
  `fetch` returns None rather than guessing: a stream plus a nanosecond is not
  a durable handle.
- **No match count.** A range query returns up to `limit` and stops. The page
  reports what it returned and says so, rather than inventing a total people
  would then reason about.

## Searching every source at once

`hub.logs("*")` returns a `FanOutLogSource` — every configured log source
behind one. Presenting it as a source rather than as a special case means every
route, dashboard panel and conformance check works unchanged; it is another
implementation of an interface that already exists, and it passes the same
suite as the backends it wraps.

With a single source configured, `logs("*")` returns that source rather than a
wrapper. A fan-out of one adds a thread pool, an intersection and a merge to
answer a question one object already answers.

Three things are hard, and none of them is the merge:

**Partial failure must be visible.** One backend down and the page still
renders — with fewer rows and no sign that anything is missing. Fewer rows
looks exactly like less data. Every source that fails is named in the warnings,
`partial` is set, and the Logs screen shows a banner rather than leaving it in
the payload.

**A merged total is a lie unless it says so.** Elasticsearch reports a real
match count; Loki returns up to `limit` and stops. Adding them produces a
number that is neither, and people reason about numbers. Whenever any
contributor could not count — or returned exactly what it was asked for, and
therefore has more — the sum is reported as a lower bound.

**Capabilities are the intersection.** If only one source can do field
statistics, serving its answer for a merged view labels one source's data as
everything's. The feature is refused instead.

Fan-out is parallel: serial would multiply latency by the number of backends
for no reason.

### What is deliberately not done

**Paging.** A merged, time-ordered page needs every source's cursor advanced
together, and each backend's cursor means something different. A cursor that
silently skips records is worse than no paging, so `cursor` is None and the
merged view is first-page only.

**Container names are not qualified by source.** A role granted `app-*` still
means `app-*`, so existing authorization keeps working exactly — and that has a
consequence worth stating plainly: **a pattern applies to every source, so
adding a source widens what existing roles can reach.** Adding one is a
deliberate administrator action and the roles page is next to it, but if that
is not the behaviour you want, the boundary to add is a per-source grant.

Two things narrow it back. A pattern may be written `source-name:pattern` to
apply to one source only, and a pattern prefixed with `-` excludes — deny wins
over every allow, in any order, so `*` with `-primary:secret-*` reaches
everything except that one family in that one store. Both live in
`patterns.py`, so the scope's boundary check and the query an adapter pushes
down are rendered from the same rules; when they were separate the check
allowed a pattern the query then read as a literal name.

**Which source answered is reported with every page.** `LogPage.sources` carries
one entry per source — how many of the rows on screen came from it, its match
count, whether that count is exact, and whether it answered at all. It is
deliberately not part of field statistics: those are a declared `Capability`
that Loki does not have, so the intersection removes them from a merged view,
and a merged view is precisely when the question is worth answering. A source
that failed keeps its row, marked, because a missing row and a zero read the
same and mean the opposite.

## Traces: one contract, two axes

OpenTelemetry defines a span, a wire protocol for writing one (OTLP), and a
naming vocabulary. It defines nothing about reading. So "an OpenTelemetry
source" is not a well-formed statement until a backend is named — Jaeger,
Tempo, Elasticsearch and ClickHouse are all written to over OTLP and none of
them is read the same way.

Two things vary independently, and the hub keeps them apart:

    TraceSource   which system, and how it is queried
                  ES query DSL / Jaeger API / TraceQL / SQL
    SpanSchema    what shape the documents are in
                  only meaningful for a general-purpose document store

`SpanSchema` exists because one Elasticsearch cluster commonly holds two
shapes: what an OpenTelemetry Collector writes in `mapping.mode: otel`, and
what Elastic APM writes. The schema is detected from the index MAPPING rather
than its name. That is why "OpenTelemetry support" is not a separate adapter
here — it is a second field vocabulary inside one.

A genuinely different adapter is needed when the QUERY API differs. Jaeger and
Tempo are both that, and they differ from each other in ways worth knowing
before choosing one:

| | Jaeger | Tempo |
|---|---|---|
| unqualified search | impossible — `service` is mandatory | `{}` matches everything |
| ids | hex everywhere | hex in search, base64 in the trace endpoint |
| times | microseconds | seconds in queries, nanoseconds in spans |
| error flag on a summary | needs the whole trace | free, from `serviceStats` |
| per-service volume | needs a metrics backend | needs a metrics backend |
| a query it cannot express | no query language to fail | HTTP 400 with a parse error |

Neither reports service volume without a separate metrics system, so both
report zero rather than a count derived from a bounded search — a number that
describes the twenty traces that came back, presented as the volume of a
service, is worse than no number.

## The Advisor across backends

Rules are pure functions over a snapshot, and that design is what made a
second backend cheap: everything that speaks HTTP lives in one collector
module, so a rule is tested against a saved dictionary and a collector can
fail without taking the report down.

Each rule declares which backends it can be evaluated against, defaulting to
Elasticsearch — the thirty-one rules written before there was a second backend
keep their meaning without being edited. A report runs only its own backend's
rules, because a Loki report listing thirty-one skipped Elasticsearch checks
buries the six that matter.

What can be checked differs enormously, and the report says so rather than
letting a short one read as a clean bill of health:

| backend | source | checks |
|---|---|---|
| Elasticsearch | the cluster APIs | 31 |
| Loki | `/config`, the whole effective configuration | 6 |
| Tempo | `/status/config` | 5 |
| VictoriaLogs | `/flags`, only what was SET | 4 |
| Jaeger | nothing — its query API describes traces, not itself | 3 |

Jaeger's three include one that exists to state the limit. A report with three
checks and no explanation reads as "this backend is fine", which is not the
same statement as "there are three things anybody can check from here".

## Not here yet

- **Service map.** The service list and error rates exist; deriving a call
  graph from span links is the next step. It is an expensive aggregation and
  must be cached.
- **Query-node capabilities.** `Prefix` and `Wildcard` do not cost the same on
  every store — some make them expensive or unsupported. The `Capability`
  mechanism can express that, but there is no per-node declaration yet.
- **An OpenSearch adapter.** The interfaces are ready; ISM and DLS differences
  need one of their own.
