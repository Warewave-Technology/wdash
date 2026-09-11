"""Security and durability rules.

These checks deliberately stay within what the Basic (free) licence offers.
Platinum-only features such as document- and field-level security are out of
scope — WDash's RBAC has to live in the application layer regardless.
"""

from ..models import Finding, NotEvaluated, Severity, rule

CATEGORY = "security"


def _node_setting(info, dotted_key):
    """Look a node setting up in both nested and flat form."""
    settings = info.get("settings") or {}
    if dotted_key in settings:
        return settings[dotted_key]
    current = settings
    for part in dotted_key.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
        if current is None:
            return None
    return current


def _is_true(value):
    return str(value).lower() == "true"


@rule(id="SEC001", category=CATEGORY, title="Cluster authentication",
      needs=("nodes_info",))
def security_disabled(snap):
    disabled = []
    for node_id, info in snap.node_infos():
        value = _node_setting(info, "xpack.security.enabled")
        # Security is on by default in ES 8; treat an absent setting as enabled
        if value is not None and not _is_true(value):
            disabled.append(snap.node_name(node_id))

    if not disabled:
        return

    yield Finding(
        rule_id="SEC001", category=CATEGORY, severity=Severity.CRITICAL,
        title="Elasticsearch security is disabled",
        evidence=f"xpack.security.enabled=false: {', '.join(disabled)}",
        impact=("Anyone who can reach the cluster over the network can read and delete "
                "every document without authenticating. WDash's RBAC only constrains "
                "requests that go through WDash; a request sent straight to Elasticsearch "
                "bypasses it entirely."),
        remediation=("Set xpack.security.enabled=true in production and create a dedicated "
                     "user for WDash. Also restrict Elasticsearch at the network layer so "
                     "only WDash can reach it (NetworkPolicy or security group): if the "
                     "application layer is the only gate, it must not be possible to walk "
                     "around it."),
        targets=disabled,
    )


@rule(id="SEC002", category=CATEGORY, title="Transport TLS", needs=("nodes_info",))
def transport_tls_disabled(snap):
    # If security is off entirely, SEC001 already reports a stronger finding
    any_security = False
    insecure = []
    for node_id, info in snap.node_infos():
        enabled = _node_setting(info, "xpack.security.enabled")
        if enabled is not None and not _is_true(enabled):
            continue
        any_security = True
        ssl = _node_setting(info, "xpack.security.transport.ssl.enabled")
        if ssl is not None and not _is_true(ssl):
            insecure.append(snap.node_name(node_id))

    if not any_security or not insecure:
        return

    yield Finding(
        rule_id="SEC002", category=CATEGORY, severity=Severity.WARNING,
        title="Inter-node traffic is unencrypted",
        evidence=f"xpack.security.transport.ssl.enabled=false: {', '.join(insecure)}",
        impact="Replication and query traffic between nodes travels in plain text. "
               "Anyone on the same network can read every indexed document.",
        remediation="Configure TLS on the transport layer. Elasticsearch 8 already "
                    "requires it for multi-node clusters.",
        targets=insecure,
    )


@rule(id="SEC003", category=CATEGORY, title="Snapshot repository",
      needs=("snapshot_repositories", "nodes_info"))
def no_snapshot_repository(snap):
    if snap.snapshot_repositories:
        return
    # Absence of data is not absence of the thing: an empty answer from a
    # cluster that listed no nodes either is not one that was reached.
    if not (snap.nodes_info or {}).get("nodes"):
        raise NotEvaluated("_nodes/info listed no nodes, so the empty "
                           "repository list is not known to be the cluster's")

    yield Finding(
        rule_id="SEC003", category=CATEGORY, severity=Severity.WARNING,
        title="No snapshot repository is registered",
        evidence="GET _snapshot returns nothing — no repository configured",
        impact=("There are no backups. Replicas protect against hardware failure, but they "
                "will not bring back an index deleted by mistake, a corrupted mapping, or "
                "a bad _reindex."),
        remediation=("Register a snapshot repository (S3, GCS, or a shared filesystem) and "
                     "take periodic snapshots with SLM. Both are available on the Basic "
                     "licence."),
        targets=[],
    )


@rule(id="SEC004", category=CATEGORY, title="Wildcard delete protection",
      needs=("cluster_settings",))
def destructive_requires_name(snap):
    value = snap.cluster_setting("action.destructive_requires_name")
    if value is None or _is_true(value):
        return

    yield Finding(
        rule_id="SEC004", category=CATEGORY, severity=Severity.WARNING,
        title="Deleting indices by wildcard is allowed",
        evidence=f"action.destructive_requires_name={value}",
        impact="A request such as DELETE /* or DELETE /logs-* can remove every index at "
               "once. One mistyped command means data loss.",
        remediation='PUT /_cluster/settings {"persistent": '
                    '{"action.destructive_requires_name": true}}',
        targets=[],
    )
