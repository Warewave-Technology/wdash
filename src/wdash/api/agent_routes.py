"""
The two endpoints an agent talks to.

    GET  /api/agent/config    what should I be checking?
    POST /api/agent/results   here is what I found

The agent pulls and pushes; WDash never connects to it. That is what lets an
agent live behind NAT, in a branch office, or on somebody's laptop — which is
the whole point of checking from where the users are rather than from where
the server is.

These routes are OUTSIDE the session login. An agent has no browser, no cookie
and no user; it carries a bearer token. `login_required` on them would be a
redirect to a sign-in page that a daemon cannot read, and the failure would
look like the agent being broken.

Three things they refuse to do:

**Accept results for monitors the agent does not run.** An ingest endpoint
that takes anything is a way to paint the whole board green. A compromised
agent should be able to lie about its own checks and nothing else.

**Say whether a token exists.** A wrong token and a disabled agent get the
same answer, for the same reason a wrong password and an unknown username do.

**Report an unreachable agent as a failing target.** That decision lives in
the source adapter rather than here, but it starts here: `last_seen_at` is
written on every exchange, and it is what tells "the target is down" apart
from "nobody has looked".
"""

import logging

from flask import Blueprint, current_app, jsonify, request

agent_bp = Blueprint("agent", __name__, url_prefix="/api/agent")

logger = logging.getLogger(__name__)

#: Results accepted in one batch. An agent that has been offline for an hour
#: has a backlog to flush, and it should flush it in pieces rather than in one
#: request the server has to hold entirely in memory.
MAX_BATCH = 500


def _authenticate():
    """The agent behind this request, or None.

    Bearer token in the Authorization header — not a query parameter, which
    would be written to every access log between here and the agent.
    """
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        return None
    store = getattr(current_app, "store", None)
    if store is None:
        return None
    return store.agents.by_token(header[7:].strip())


def _refused():
    # One message for a bad token, a disabled agent and a deleted one. Telling
    # them apart is telling somebody holding a stolen token which half of it
    # is wrong.
    return jsonify({"error": "Unknown or disabled agent."}), 401


@agent_bp.route("/config")
def config():
    """What this agent should be checking, and how often."""
    agent = _authenticate()
    if agent is None:
        return _refused()

    store = current_app.store
    store.agents.seen(agent["id"], version=request.headers.get("X-Agent-Version"))

    monitors = store.monitors.for_agent(agent["id"])
    return jsonify({
        "agent": {"id": agent["id"], "name": agent["name"]},
        "monitors": [{
            "id": m["id"], "name": m["name"], "kind": m["kind"],
            "target": m["target"],
            "interval_seconds": m["interval_seconds"],
            "timeout_seconds": m["timeout_seconds"],
            "assertions": m["assertions"],
        } for m in monitors],
        # A version the agent can compare against what it already has, so a
        # poll that changes nothing costs one comparison rather than a
        # reschedule of everything.
        "version": _configuration_version(monitors),
    })


def _configuration_version(monitors):
    """A hash of what was sent, so the agent can tell a change from a poll.

    Content-derived rather than a counter: a counter has to be bumped by
    everything that edits a monitor, and the one place that forgets is the one
    that matters.
    """
    import hashlib
    import json
    payload = json.dumps(
        [[m["id"], m["kind"], m["target"], m["interval_seconds"],
          m["timeout_seconds"], m["assertions"]] for m in monitors],
        sort_keys=True, default=str)
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


@agent_bp.route("/results", methods=["POST"])
def results():
    """A batch of check results."""
    agent = _authenticate()
    if agent is None:
        return _refused()

    payload = request.get_json(silent=True) or {}
    batch = payload.get("results")
    if not isinstance(batch, list):
        return jsonify({"error": "Expected a JSON body with a 'results' list."}), 400
    if len(batch) > MAX_BATCH:
        return jsonify({
            "error": f"At most {MAX_BATCH} results per request.",
            "accepted": 0,
        }), 413

    store = current_app.store
    store.agents.seen(agent["id"], version=request.headers.get("X-Agent-Version"))

    try:
        stored = store.results.record(agent["id"], batch)
    except Exception as exc:
        # The agent will retry, so this must not look like acceptance —
        # a 500 it can act on beats a 200 that silently drops the batch.
        logger.error(f"agent {agent['name']}: could not store results: {exc}")
        return jsonify({"error": "Could not store the results."}), 500

    # Retention runs here, at most once an hour across the installation. The
    # endpoint that grows the table is the natural place to shrink it: no
    # scheduler, no extra thread, and an installation nobody reports into has
    # nothing to prune.
    #
    # After the response is decided, and never allowed to fail it: the agent's
    # results are already safe, and losing them to a housekeeping error would
    # be the worst possible trade.
    try:
        store.results.prune_if_due(store.settings)
    except Exception as exc:
        logger.error(f"could not prune monitor results: {exc}")

    # `accepted` rather than a bare 204: an agent that reported for a monitor
    # it does not run needs to know the difference between "stored" and
    # "received and dropped", or it keeps sending them for ever.
    return jsonify({"accepted": stored, "received": len(batch)})
