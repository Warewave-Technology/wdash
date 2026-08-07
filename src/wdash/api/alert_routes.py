"""
What has fired, and what never reached anybody.

The second half is the point. A delivery that failed and was not written down
is an alert nobody received and nobody knows was missed — the worst of both,
because the absence of alerts reads as "nothing is wrong".
"""

from flask import Blueprint, current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

alert_bp = Blueprint("alerts", __name__)

PER_PAGE = 50


@alert_bp.route("/alerts")
@login_required
def history():
    if not current_user.has_permission("monitors:read"):
        flash("Access denied: alerts require the monitors:read permission.",
              "error")
        return redirect(url_for("index"))

    store = getattr(current_app, "store", None)
    if store is None:
        return render_template("alerts.html", entries=[], pager=None,
                               undelivered_only=False, rules={}, total=0,
                               undelivered=0)

    undelivered_only = request.args.get("undelivered") == "1"
    page = max(1, request.args.get("page", type=int) or 1)
    total = store.alert_history.count(undelivered_only=undelivered_only)

    pages = max(1, (total + PER_PAGE - 1) // PER_PAGE)
    page = min(page, pages)
    entries = store.alert_history.recent(
        limit=PER_PAGE, offset=(page - 1) * PER_PAGE,
        undelivered_only=undelivered_only)

    return render_template(
        "alerts.html",
        entries=entries,
        # Names, so a row says "Payments API" rather than a pair of uuids.
        rules={r["id"]: r for r in store.rules.all()},
        undelivered_only=undelivered_only,
        undelivered=store.alert_history.count(undelivered_only=True),
        total=total,
        pager=({"page": page, "pages": pages, "total": total,
                "first": (page - 1) * PER_PAGE + 1,
                "last": min(total, page * PER_PAGE),
                "has_previous": page > 1, "has_next": page < pages,
                "numbers": [n for n in range(page - 2, page + 3)
                            if 1 <= n <= pages]}
               if pages > 1 else None))
