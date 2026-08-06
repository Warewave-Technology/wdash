"""
Who can see which dashboard.

`dashboard:view` used to mean "see every dashboard". Panel data was still
filtered by the viewer's own boundaries, so nothing leaked — but a dashboard's
NAME and QUERY are themselves information. `payment-fraud-investigation` over
`fraud-*` tells you something whether or not you can read the index.

The rule
--------
**You can see a dashboard if you could see its data.** A dashboard resolving to
no container you may reach is one you could never have used, so hiding it costs
nothing and stops the list from advertising what exists.

That rule needs no new concept and cannot drift out of step with the data
boundary, because it IS the data boundary. What it cannot express is intent: an
author who wants a dashboard kept to themselves even among colleagues who share
their access. So `visibility` exists for exactly that, and nothing more.

    shared   (default) visible to anyone who can reach its data
    private            the author, and administrators

Two exceptions, both deliberate:

* **Authors always see their own.** Otherwise a dashboard pointing at an index
  that does not exist yet would be invisible to the person who just wrote it,
  which reads as "it did not save".
* **`system:admin` sees every dashboard.** Editing and deleting somebody
  else's already requires it; being unable to see the thing you are allowed to
  delete is not a boundary, it is a puzzle.
"""

SHARED = "shared"
PRIVATE = "private"

VISIBILITIES = {
    SHARED: ("Shared",
             "Anyone who can reach this dashboard's data can see it."),
    PRIVATE: ("Private",
              "Only you and administrators, even if others can reach the "
              "same data."),
}

#: What a dashboard stored before this existed gets. Shared, so nothing
#: disappears on upgrade — the boundary rule still applies, which is the point.
DEFAULT = SHARED


def normalise(value):
    value = (value or "").strip().lower()
    return value if value in VISIBILITIES else DEFAULT


def can_view(dashboard, username, is_admin, reachable_containers):
    """May this person see that this dashboard exists?

    `reachable_containers` is what the dashboard resolves to for THIS viewer —
    already intersected with their scope. Passing it in rather than computing
    it here keeps the rule testable without a cluster, and keeps the caller
    honest about doing the intersection.
    """
    if dashboard.created_by == username:
        return True
    if is_admin:
        return True
    if getattr(dashboard, "visibility", DEFAULT) == PRIVATE:
        return False
    return bool(reachable_containers)


def explain(dashboard, username, is_admin, reachable_containers):
    """Why it is or is not visible. For the list page and for tests."""
    if dashboard.created_by == username:
        return "yours"
    if is_admin:
        return "visible to administrators"
    if getattr(dashboard, "visibility", DEFAULT) == PRIVATE:
        return "private to its author"
    if not reachable_containers:
        return "none of its data is within your access"
    return "shared"
