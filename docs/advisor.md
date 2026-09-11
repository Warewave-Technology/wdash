# Cluster Advisor

Inspects the connected Elasticsearch cluster and reports misconfigurations with
concrete fixes. It is strictly read-only and never changes a setting.

## Design

Two stages, with a hard boundary between them:

```
snapshot = collect(es)          # I/O   — gather raw data
report   = run_rules(snapshot)  # pure  — run the rules over the snapshot
```

Rules never see a live connection. Three consequences follow:

1. **Testability** — a snapshot taken from a real cluster is used directly as a
   fixture. The test suite needs no Elasticsearch.
2. **Determinism** — the same snapshot always produces the same report.
3. **Portability** — rules map one to one onto a `Rule` struct with a function
   field in any language.

Collection is parallel and each call is isolated: if one fails, that field
stays empty, the error is recorded under `collection_errors`, and the others
continue. The whole collection has a 30-second budget. A call still running
when it runs out is recorded as not collected, and everything that did arrive
is kept. If a rule raises, the report survives and the error is recorded under
`errors`. The Advisor itself must not become an outage.

A rule whose input was not collected is not run. It is listed under
`not_evaluated` with the reason, and so is a rule that could not read what it
found (`NotEvaluated`). Both used to count as passed, so a cluster that
refused every call scored 100 with all 31 rules passed. Now:

- only a complete report says every rule passed;
- a partial report says which rules could not look;
- a report where nothing could be evaluated says "Analysis unavailable" and
  has no score (`"score": null`, `"complete": false` in the JSON).

## Usage

### Web

`/advisor`, requires the `system:admin` permission. The report is cached for
five minutes; `?refresh=1` regenerates it.

### API

| Endpoint | Description |
|---|---|
| `GET /api/advisor/report` | The report as JSON |
| `GET /api/advisor/rules` | Rule catalogue |

### Command line

```bash
# Live cluster
PYTHONPATH=src python -m wdash.advisor --url http://localhost:9200

# Save a snapshot (to produce a fixture)
PYTHONPATH=src python -m wdash.advisor --save-snapshot tests/fixtures/prod.json

# Run against a saved snapshot — no cluster needed
PYTHONPATH=src python -m wdash.advisor --from-snapshot tests/fixtures/prod.json

# CI: exit 1 when a critical finding exists
PYTHONPATH=src python -m wdash.advisor --fail-on critical
```

`--from-snapshot` is the fastest loop while writing rules: capture once, then
run the rule as often as you like.

The exit status:

| Status | Meaning |
|---|---|
| 0 | Nothing to report at the `--fail-on` level, or no `--fail-on` given |
| 1 | A finding at or above the `--fail-on` level |
| 2 | Nothing could be evaluated. With `--fail-on`, also any call that was not collected or any rule that could not look. The reasons go to stderr |

A finding at the level still exits 1 from a partial report, because what was
found is found. Nothing found in a partial report is not the same as nothing
there, so that exits 2.

The client checks the cluster's certificate. Set `ELASTICSEARCH_CA_CERTS` to
the CA that signed it. `ELASTICSEARCH_VERIFY_CERTS=false` (the web process's
own switch) or `--insecure` turns the check off. `ELASTICSEARCH_USERNAME` and
`ELASTICSEARCH_PASSWORD` are sent with every request, and without the check
they go to whoever answers. The web process defaults to no check, so that an
upgrade does not cut a deployment off from its cluster. The command line is
run by hand or in CI, where a refused certificate is only a message.

## Rules

| ID | Category | Title |
|---|---|---|
| `CLU001` | cluster | Cluster status |
| `CLU002` | cluster | JVM heap usage |
| `CLU003` | cluster | Heap above the compressed oops threshold |
| `CLU004` | cluster | Heap to system memory ratio |
| `CLU005` | cluster | Memory locking (mlockall) |
| `CLU006` | cluster | Disk watermarks |
| `CLU007` | cluster | Thread pool rejections |
| `CLU008` | cluster | Circuit breaker trips |
| `CLU009` | cluster | Master-eligible node count |
| `IDX001` | indices | Refresh interval |
| `IDX002` | indices | Lifecycle policy *(Elasticsearch only)* |
| `IDX003` | indices | Index sorting |
| `IDX004` | indices | Compression codec |
| `IDX005` | indices | Slow query log |
| `MAP001` | mappings | Aggregated fields are aggregatable |
| `MAP002` | mappings | Unbounded dynamic mapping |
| `MAP003` | mappings | Field count limit |
| `MAP004` | mappings | Redundant .keyword on a large text field |
| `MAP005` | mappings | Time field |
| `QRY001` | queries | Request cache hit rate |
| `QRY002` | queries | Query cache hit rate |
| `QRY003` | queries | Fielddata memory usage |
| `SEC001` | security | Cluster authentication |
| `SEC002` | security | Transport TLS |
| `SEC003` | security | Snapshot repository |
| `SEC004` | security | Wildcard delete protection |
| `SHD001` | shards | Shards per node |
| `SHD002` | shards | Oversized shard |
| `SHD003` | shards | Index split into more shards than its size warrants |
| `SHD004` | shards | Replica configuration |
| `SHD005` | shards | Cluster shard limit |

Two rules are specific to how WDash queries data:

- **`MAP001`** checks the mapping of the fields WDash aggregates on (`level`,
  `service`, `host`, `environment`). If one is analysed text with no `.keyword`
  sub-field the query fails and the dashboard panel renders empty.
- **`QRY001`** checks the shard request cache hit rate. A rate near zero
  usually means query time bounds are generated at sub-second precision, so
  every request produces a unique cache key and the cache never hits.

## Adding a rule

```python
from ..models import Finding, Severity, rule

@rule(id="IDX006", category="indices", title="Short description",
      needs=("index_settings",))    # what the verdict depends on
def my_check(snapshot):
    offenders = [i for i in snapshot.user_indices()
                 if snapshot.index_setting(i, "index.some.setting") is None]
    if not offenders:
        return                      # no findings -> the rule counts as passed

    yield Finding(
        rule_id="IDX006", category="indices", severity=Severity.WARNING,
        title="Short summary of what was observed",
        evidence="...",             # REAL values — this is what earns trust
        impact="...",               # why it matters
        remediation="...",          # a concrete fix, ideally an API call
        targets=offenders,
    )
```

Rules live in `src/wdash/advisor/rules/` under category modules; a new category
must also be imported in `rules/__init__.py`.

Three principles:

1. **Concrete evidence.** `evidence` must carry the observed values. Not
   "misconfigured" but "bad-logs: 5 shards totalling 5.2MB".
2. **Actionable remediation.** "Review this" is not a fix. Give a runnable API
   call where possible. A test enforces it
   (`test_every_finding_is_actionable`).
3. **Absence of data is not absence of the thing.** Declare every collected
   field the verdict depends on with `needs=`. When one of them failed, the
   rule is not run and the report says so. A test reads what each rule
   touches and fails when it reads more than it declares
   (`test_every_rule_declares_what_it_reads`). When the data arrived but the
   rule cannot read it, raise `NotEvaluated` with the reason rather than
   returning: returning is a pass. Examples are a watermark in a form it does
   not know, a setting not in `/config`, or no data nodes to divide by.

### Choosing thresholds

Thresholds have to be high enough not to cry wolf and low enough not to miss a
real problem. Examples:

- `SHD003` only flags *multi-shard* indices below 1GB per shard — a small
  single-shard index is not a problem.
- `QRY001` does not run at all below 50 samples; the ratio is meaningless on a
  fresh cluster.
- `IDX004` only looks at indices above 10GB; changing the codec on a small
  index gains nothing.

## Testing

```bash
python -m unittest tests.test_advisor tests.test_advisor_routes \
    tests.test_advisor_backends tests.test_advisor_cli
```

The tests use snapshots under `tests/fixtures/` and need no Elasticsearch.
Local listeners stand in for what a fixture cannot be: a port nothing
listens on, a cluster that answers 401, a sign-in page answering 200, and a
TLS listener with a certificate nobody vouches for.

To refresh the fixtures after changing the sample data:

```bash
cd lab && ./lab.sh up && ./lab.sh seed --reset
cd .. && PYTHONPATH=src python -m wdash.advisor \
    --save-snapshot tests/fixtures/lab-cluster.json
```

The lab environment deliberately contains misconfigured indices (see
`lab/README.md`). That lets us verify both that the rules fire and that they
stay quiet on healthy indices — the second matters at least as much as the
first.

## Known limits

- **The report cache is per process.** Each gunicorn worker keeps its own copy.
  Acceptable while the TTL is short; report history should move to shared
  storage alongside the rest of the metadata.
- **Cumulative counters.** Thread pool rejections, circuit breaker trips and
  cache ratios are cumulative since node start. On a long-running node an old
  event is still reported. The finding text says so.
- **Point-in-time readings.** Heap usage is a single sample; it looking high
  just before a garbage collection is normal.
- **No trend.** Each report is an independent snapshot today. Writing snapshots
  to a metadata index and showing change over time ("shard count tripled in a
  month") would be more useful than a single photograph.
- **OpenSearch is only partly supported.** The rule infrastructure is
  distribution-aware (the `distributions` constraint), but only `IDX002` is
  marked. Moving to OpenSearch would need ISM rules.
