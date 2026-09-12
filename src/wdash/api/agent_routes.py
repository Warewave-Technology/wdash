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
    checks, unreadable = [], set()
    for m in monitors:
        # The agent makes the request, so it needs the credentials. This is
        # the ONLY place they leave the database — not the config page, not
        # the audit trail, not a result. Over TLS, to a caller that proved it
        # holds this agent's token.
        filled = _credentials_for(store, m)
        if filled.get("config_error"):
            unreadable.add(m["id"])
        checks.append({
            "id": m["id"], "name": m["name"], "kind": m["kind"],
            "target": _target_for(m),
            "interval_seconds": m["interval_seconds"],
            "timeout_seconds": m["timeout_seconds"],
            "assertions": m["assertions"],
            # What this check trusts, or waives. The pasted certificate is
            # public and the agent needs it to build a trust store of its
            # own: it owns no files and reads nothing local, so a path here
            # would be a configuration error on each agent host that WDash
            # could not see and that would look like an outage.
            "tls": m.get("tls") or {},
            **filled,
        })

    return jsonify({
        "agent": {"id": agent["id"], "name": agent["name"]},
        "monitors": checks,
        # A version the agent can compare against what it already has, so a
        # poll that changes nothing costs one comparison rather than a
        # reschedule of everything.
        "version": _configuration_version(monitors, unreadable),
    })


def _credentials_for(store, monitor):
    """The request (and a journey's steps) with the credentials filled in.

    One monitor whose secrets will not decrypt does not spoil the others, and
    it is not sent as a request with the credential quietly missing either:
    the agent is told why, verbatim, and reports the check down with that
    sentence rather than measuring a 401 the target was right to send.
    """
    from ..store.monitoring import MonitoringError
    try:
        return {"request": _request_for(store, monitor),
                **_journey_for(store, monitor)}
    except MonitoringError as exc:
        logger.error(f"check '{monitor.get('name')}' cannot be configured: "
                     f"{exc}")
        return {"request": {}, "config_error": str(exc)}


def _expiry_only(monitor):
    """Whether this check was told not to verify the certificate."""
    from ..store.monitoring import EXPIRY_ONLY, tls_mode
    return tls_mode(monitor.get("tls")) == EXPIRY_ONLY


def _without_userinfo(url):
    """A URL with any `user:password@` taken out of it."""
    from urllib.parse import urlsplit, urlunsplit
    try:
        parts = urlsplit(url or "")
    except ValueError:
        return url
    if "@" not in (parts.netloc or ""):
        return url
    return urlunsplit(parts._replace(netloc=parts.netloc.rsplit("@", 1)[-1]))


def _target_for(monitor):
    """The address this check is given, with no credential written into it.

    The fourth channel, and the one `_request_for` cannot reach: a password
    in the ADDRESS is not in `request` and not in `secrets`, and `requests`
    reads it straight back off the URL. So "an expiry-only check is sent
    nothing it would send" has to cover the target as well, or the one place
    any of this leaves the database hands it over anyway.
    """
    target = monitor.get("target")
    if not _expiry_only(monitor):
        return target
    stripped = _without_userinfo(target)
    if stripped != target:
        # Loud for the same reason the request is: the store refuses to SAVE
        # this pair, so a row holding it was hand-edited or written by an
        # older build, and the check failing to sign in an hour later says
        # nothing about why.
        logger.error(
            f"check '{monitor.get('name')}' does not verify the certificate, "
            f"so the credentials written into its address were not sent to "
            f"the agent")
    return stripped


def _steps_for(monitor, steps):
    """A journey's steps, with no credential written into a `goto`."""
    if not _expiry_only(monitor):
        return steps
    out = []
    for step in steps:
        step = dict(step or {})
        if step.get("kind") == "goto":
            step["value"] = _without_userinfo(step.get("value"))
        out.append(step)
    return out


def _request_for(store, monitor):
    """The public request configuration with its credentials filled back in."""
    request = dict(monitor.get("request") or {})
    if _expiry_only(monitor):
        # NOTHING, not merely no sealed values. A check that does not verify
        # the certificate is talking to whatever answered, and a header typed
        # into the plain box — X-Tenant-Token, X-Session — is stored in the
        # open and would go out all the same; so would a basic-auth username
        # with no stored password, which `requests` prepares into a real
        # Authorization header.
        #
        # Loud, because the store refuses to SAVE this combination: a row
        # that holds both was hand-edited or written by an older build, and a
        # silent 401 an hour later is not something anybody can act on.
        if request or monitor.get("has_credentials"):
            logger.error(
                f"check '{monitor.get('name')}' does not verify the "
                f"certificate, so nothing it was configured to send was sent "
                f"to the agent — no headers, no cookies, no authentication")
        return {}
    # A journey's secrets are a journey's, and go with its steps (see
    # `_journey_for`). Read as request secrets, one named `headers` was
    # merged as a header dictionary: the configuration answered 500 to every
    # agent that ran the journey — every agent, if it was unassigned — so
    # none of them picked up anything, http checks included.
    if monitor.get("kind") == "browser" or not monitor.get("has_credentials"):
        return request

    secrets = store.monitors.credentials(monitor["id"])
    headers = dict(request.get("headers") or {})
    headers.update(secrets.get("headers") or {})
    if headers:
        request["headers"] = headers
    if secrets.get("cookies"):
        request["cookies"] = secrets["cookies"]
    # `cookie_names` is for a screen; the agent has the cookies themselves.
    request.pop("cookie_names", None)

    auth = dict(request.get("auth") or {})
    if auth.get("type") == "basic" and secrets.get("auth_password"):
        auth["password"] = secrets["auth_password"]
    if auth.get("type") == "bearer" and secrets.get("auth_token"):
        auth["token"] = secrets["auth_token"]
    if auth:
        request["auth"] = auth
    return request


def _journey_for(store, monitor):
    """A journey's steps and the secrets they name. Empty for other kinds.

    Sent as a pair rather than with the placeholders already substituted: the
    agent resolves them at the moment it types, so a password is one value in
    one call and not a string that has been through a step list, a JSON body
    and a log line on the way.
    """
    if monitor.get("kind") != "browser":
        return {}
    out = {"steps": _steps_for(monitor, monitor.get("steps") or [])}
    if _expiry_only(monitor):
        # Same rule as an http check's headers, and the same reason: a
        # journey that does not verify the certificate types its password
        # into whatever answered. The store refuses to save the pair, so
        # reaching this is a hand-edited row — the step then fails with "this
        # journey uses {{ secret.x }} and there is no such secret", which
        # names the cause, rather than a sign-in that quietly gives it away.
        if monitor.get("has_credentials"):
            logger.error(
                f"journey '{monitor.get('name')}' does not verify the "
                f"certificate, so its secrets were not sent to the agent")
        return out
    if monitor.get("has_credentials"):
        out["secrets"] = store.monitors.credentials(monitor["id"])
    return out


def _configuration_version(monitors, unreadable=()):
    """A hash of what was sent, so the agent can tell a change from a poll.

    Content-derived rather than a counter: a counter has to be bumped by
    everything that edits a monitor, and the one place that forgets is the one
    that matters.
    """
    import hashlib
    import json
    # The request configuration is part of what the agent runs, so a change
    # to a header has to move the version — otherwise the agent keeps sending
    # the old one until something else happens to change.
    #
    # `updated_at` rather than the credentials themselves. Hashing a secret
    # would put it in a value that is logged and compared; hashing
    # `has_credentials` would not move when a password is REPLACED, so a
    # rotated credential would never reach the agent. Every edit bumps the
    # timestamp, including one that only changes a secret.
    #
    # Whether the credentials could be READ is part of what was sent too: a
    # check whose secret will not decrypt goes out as `config_error` with no
    # request, and nothing in the stored row differs between that and the
    # working version. Left out, the version was byte-identical before and
    # after somebody restored WDASH_ENCRYPTION_KEY, `_poll_config` returned
    # early on the unchanged version, and the agent went on reporting the
    # check down with "the key has probably changed" until it was restarted.
    # The FACT, never the reason: the reason is a sentence, and a sentence
    # that is reworded is not a configuration change.
    #
    # The TLS setting is in here for the same reason the request is: it is
    # part of what the agent runs. It is NOT covered by `updated_at` — that
    # moves on every edit and would make this test pass whatever the payload
    # held, which is exactly how a field gets left out of a version hash and
    # nobody notices.
    unreadable = set(unreadable)
    payload = json.dumps(
        [[m["id"], m["kind"], m["target"], m["interval_seconds"],
          m["timeout_seconds"], m["assertions"], m.get("request"),
          m.get("tls"), m.get("updated_at"), m["id"] in unreadable]
         for m in monitors],
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
