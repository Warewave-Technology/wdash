"""
Every permission WDash understands.

Until this file existed, permission names were bare strings scattered through
route code. Three consequences followed, and all three were measured:

  * the configuration page accepted anything. `logs:raed` saved cleanly, granted
    nothing, and said nothing — on the one page whose entire job is access
    control.
  * the UI could only offer a free-text box, which is what made the typo
    possible in the first place.
  * nothing could tell whether a permission was still used by any route, so
    dead names would accumulate silently.

A catalogue fixes all three, and one static test keeps it honest: every
`has_permission("x")` in the codebase must name something here.

The descriptions are shown to administrators. They should say what somebody
CAN DO, not restate the name.
"""

from collections import OrderedDict

#: name -> (group, label, what it actually allows)
PERMISSIONS = OrderedDict([
    ("logs:read", (
        "Logs", "Read logs",
        "Open the Logs screen, search it, and read a record with its "
        "surrounding lines. Which logs are visible is decided separately, by "
        "the role's log containers.")),
    ("traces:read", (
        "Traces", "Read traces",
        "Open the Traces screen, search it, and open a trace waterfall. Which "
        "traces are visible is decided by the role's trace stores and "
        "services.")),
    ("monitors:read", (
        "Monitors", "Read synthetic monitors",
        "Open the Monitors screen: which endpoints are being probed, whether "
        "they answered, and the TLS certificates the checks saw. Unlike logs "
        "and traces this is NOT narrowed further by the role's containers — "
        "a monitor is about an endpoint, not about an index, and the role's "
        "log patterns say nothing about which endpoints somebody may see. "
        "Grant it to whoever should see the uptime of everything it "
        "watches.")),
    ("dashboard:view", (
        "Dashboards", "View dashboards",
        "See the dashboard list and open any dashboard. Panel data is still "
        "filtered by the role's own boundaries.")),
    ("dashboard:create", (
        "Dashboards", "Create dashboards",
        "Build new dashboards. A dashboard cannot reach past its author's own "
        "boundaries.")),
    ("dashboard:edit", (
        "Dashboards", "Edit dashboards",
        "Change dashboards you created. Editing somebody else's also needs "
        "system:admin.")),
    ("dashboard:delete", (
        "Dashboards", "Delete dashboards",
        "Delete dashboards you created. Deleting somebody else's also needs "
        "system:admin.")),
    ("system:admin", (
        "Administration", "Administer WDash",
        "Reach the configuration page: data sources, identity providers and "
        "roles. Also the Cluster Advisor and the debug endpoints. This is NOT "
        "a superuser — it grants no access to logs or traces on its own.")),
])

#: Removed but still present in stored roles. Mapped rather than dropped, so an
#: upgrade does not quietly narrow somebody's access.
RETIRED = {
    # Searching is reading. Splitting them produced two roles that could not
    # be used: `logs:read` alone opened a page where every search failed, and
    # `logs:search` alone worked in the API while the page refused to load.
    "logs:search": "logs:read",
}


def known(name):
    return name in PERMISSIONS


def label(name):
    return PERMISSIONS[name][1] if name in PERMISSIONS else name


def description(name):
    return PERMISSIONS[name][2] if name in PERMISSIONS else ""


def grouped():
    """Permissions by group, in declaration order, for the config form."""
    groups = OrderedDict()
    for name, (group, item_label, item_description) in PERMISSIONS.items():
        groups.setdefault(group, []).append(
            {"name": name, "label": item_label, "description": item_description})
    return groups


def normalise(names):
    """Clean a submitted list. Returns (permissions, unknown, renamed).

    Retired names are translated rather than dropped: an upgrade must not
    quietly narrow what a role could do. Unknown names are reported to the
    caller, never stored — a permission that grants nothing while looking
    configured is worse than a rejected one.
    """
    permissions, unknown, renamed = [], [], []
    for raw in names or []:
        name = (raw or "").strip()
        if not name:
            continue
        if name in RETIRED:
            replacement = RETIRED[name]
            renamed.append((name, replacement))
            name = replacement
        if not known(name):
            unknown.append(name)
            continue
        if name not in permissions:
            permissions.append(name)

    # Keep catalogue order so two roles with the same permissions store the
    # same list, which makes them comparable and diffable.
    ordered = [name for name in PERMISSIONS if name in permissions]
    return ordered, unknown, renamed
