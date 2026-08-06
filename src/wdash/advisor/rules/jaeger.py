"""
Jaeger checks.

There are three, and that is the honest number. Jaeger's query API describes
traces, not the deployment: there is no configuration endpoint, and the
Prometheus metrics live on an admin port that a deployment may not publish.
Demanding a second URL from every operator to serve an advisor is a worse
trade than checking what can be checked and saying so.

So these work from what `/api/services` and `/api/metrics/calls` can answer,
and one of them exists specifically to say that the rest cannot be checked —
a report that looks thorough while covering nothing is worse than a short one
that admits its reach.
"""

from ..models import Finding, Severity, rule

JAEGER = ("jaeger",)
DOCS = "https://www.jaegertracing.io/docs/latest/deployment/"

#: Above this, a service list has usually stopped being a list of services.
CARDINALITY_LIMIT = 500


@rule("JAEGER001", "cardinality", "The service list is a list of services",
      backends=JAEGER)
def service_cardinality(snapshot):
    """Thousands of services means `service.name` is carrying something else.

    Almost always an identifier that varies per request — a pod name, a
    tenant, a request id — spliced into the service name. The effect is that
    the service picker becomes unusable and the storage index grows in a
    dimension nobody intended.
    """
    services = snapshot.facts.get("services")
    if services is None:
        return
    count = len(services)
    if count <= CARDINALITY_LIMIT:
        return
    yield Finding(
        rule_id="JAEGER001", category="cardinality",
        severity=Severity.WARNING,
        title=f"{count:,} distinct service names",
        evidence=f"/api/services returned {count:,} names, for example: "
                 f"{', '.join(sorted(services)[:3])}",
        impact="A service list this long usually means an identifier that "
               "varies per request has been spliced into service.name. The "
               "service picker stops being usable and the index grows in a "
               "dimension nobody chose.",
        remediation="Check what the producers set as service.name. A pod "
                    "name, tenant or request id belongs in a resource "
                    "attribute, not in the service identity.",
        targets=[snapshot.source_name], docs_url=DOCS)


@rule("JAEGER002", "observability", "Service metrics are available",
      backends=JAEGER)
def metrics_api(snapshot):
    """`/api/metrics/*` answers HTTP 501 without a metrics backend.

    WDash does not read it, so nothing here breaks. It is worth reporting
    because it is why the service list shows no volume — and somebody
    comparing it with the Elasticsearch source will otherwise think WDash is
    losing the counts.
    """
    status = snapshot.facts.get("metrics_api")
    if status is None or status != 501:
        return
    yield Finding(
        rule_id="JAEGER002", category="observability",
        severity=Severity.INFO,
        title="Jaeger cannot report service metrics",
        evidence="/api/metrics/calls answered HTTP 501: metrics querying is "
                 "disabled",
        impact="No span counts or error rates per service. WDash therefore "
               "shows the service list without volume — which looks like "
               "missing data next to a source that has it.",
        remediation="Wire up a metrics backend (the SPM setup: a "
                    "span-metrics connector writing to Prometheus, and "
                    "Jaeger's PROMETHEUS_SERVER_URL pointing at it), or accept "
                    "that this source reports names only.",
        targets=[snapshot.source_name], docs_url=DOCS)


@rule("JAEGER003", "coverage", "What the Advisor can see here", backends=JAEGER)
def limited_visibility(snapshot):
    """Always reported. Deliberately.

    A report with three checks and no explanation reads as "this backend is
    fine". It is not the same statement as "there are three things anybody
    can check from here", and the difference matters to whoever is deciding
    whether the Advisor has looked.
    """
    yield Finding(
        rule_id="JAEGER003", category="coverage",
        severity=Severity.INFO,
        title="Only the query API can be inspected",
        evidence="Jaeger has no configuration endpoint. Its Prometheus "
                 "metrics are on a separate admin port that this deployment "
                 "does not have to publish, and WDash does not ask for one.",
        impact="Storage backend, sampling, retention and ingest limits cannot "
               "be checked from here. A clean report for this source is a "
               "narrower statement than a clean report for Elasticsearch or "
               "Tempo.",
        remediation="Nothing to fix. Check retention and storage in whatever "
                    "configures this Jaeger — the Helm values or the "
                    "collector configuration — rather than expecting to see "
                    "them here.",
        targets=[snapshot.source_name], docs_url=DOCS)
