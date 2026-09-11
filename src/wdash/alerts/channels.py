"""
Where an alert goes.

One kind to begin with: a webhook. Slack, Teams, PagerDuty, Opsgenie and
Alertmanager all accept one, so a single implementation reaches every common
destination — and the shape follows `store/forwarding.py`, which already sends
the audit trail to Splunk and Elasticsearch.

The payload is JSON with a flat, stable set of fields. Not a Slack block, not
a PagerDuty event: a receiving side that wants those has a transform in front
of it, and a monitoring tool that speaks one vendor's dialect has to speak
every vendor's dialect within a year.
"""

import json
import logging

logger = logging.getLogger(__name__)

WEBHOOK = "webhook"
CHANNEL_KINDS = (WEBHOOK,)

#: How long to wait for the receiving end. Short: a channel that hangs holds
#: up every other alert in the same evaluation, and an alert that arrives two
#: minutes late has already been beaten by somebody noticing.
TIMEOUT = 10


class DeliveryError(RuntimeError):
    """The alert did not get there. Recorded, never swallowed."""


def payload(rule, decision, transition):
    """What gets posted. One shape for both transitions.

    `firing` and `resolved` in the same envelope rather than two, because a
    receiver matching on `subject` needs to pair them — and a resolution that
    does not look like the alert it resolves cannot be paired.
    """
    return {
        "wdash": "alert",
        "transition": transition,          # firing | resolved
        "rule": {"id": rule.get("id"), "name": rule.get("name"),
                 "kind": rule.get("kind")},
        "subject": decision.subject,
        "name": decision.label,
        "detail": decision.detail,
        # When it STARTED, not when this message was sent. "down since 03:12"
        # is what somebody woken at 04:00 needs; "as of 04:00" is what they
        # already know.
        "since": decision.since.isoformat() if decision.since else None,
    }


def send(channel, secrets, body, session=None):
    """Deliver one alert. Raises DeliveryError with a readable reason.

    `secrets` holds whatever must not be in the stored configuration — an
    Authorization header, a token embedded in the URL by the receiver.
    """
    kind = (channel.get("kind") or "").lower()
    if kind != WEBHOOK:
        raise DeliveryError(f"'{kind}' is not a channel type this can send to.")

    config = channel.get("config") or {}
    url = (secrets or {}).get("url") or config.get("url")
    if not url:
        raise DeliveryError("This channel has no URL.")

    headers = {"Content-Type": "application/json",
               "User-Agent": "wdash-alerts"}
    headers.update(config.get("headers") or {})
    sealed = (secrets or {}).get("headers") or {}
    headers.update(sealed)

    import requests
    client = session or requests
    try:
        response = client.post(url, timeout=TIMEOUT, headers=headers,
                               data=json.dumps(body))
    except Exception as exc:
        raise DeliveryError(_redact(str(exc), url, headers, sealed)) from exc

    if response.status_code >= 400:
        # The body, trimmed. A webhook that refuses usually says why — "no
        # such channel", "token revoked" — and that sentence is the whole
        # answer to why alerts stopped arriving.
        detail = (response.text or "")[:300].strip()
        raise DeliveryError(
            _redact(f"the receiver answered {response.status_code}"
                    f"{': ' + detail if detail else ''}", url, headers,
                    sealed))
    return response.status_code


#: Header names that carry a credential wherever they are written.
_SECRET_HEADERS = ("authorization", "x-api-key", "cookie")

#: Shorter than this, a part of a URL is a word, not a credential: `/hook`
#: and `/alerts` must not blank out ordinary words in the message.
_URL_PART_MIN = 9


def _redact(text, url, headers, sealed=None):
    """Keep the credential out of the stored error.

    The failure is written to the alert history and shown on a screen. A
    webhook URL is itself a secret for Slack and Teams — the path IS the
    credential — so it never appears in a message. Nor does any header that
    was sealed, whatever it is called.
    """
    text = str(text)
    values = _url_secrets(url) if url else []
    values += [str(value) for value in (sealed or {}).values() if value]
    values += [str(value) for name, value in (headers or {}).items()
               if name.lower() in _SECRET_HEADERS and value]
    # Longest first, so a value that contains another is not left in part.
    for value in sorted(set(values), key=len, reverse=True):
        if len(value) > 3:
            text = text.replace(value, "***")
    return text


def _url_secrets(url):
    """Every part of a webhook URL that could be its credential.

    Not only the last segment. Slack keeps it in the last three, Zapier's
    catch hooks end in a slash — after which the last segment is empty and
    the one before it went into the history as sent — and others put it in
    the query string or the user part. The host stays: "could not connect
    to hooks.example" is the reason, and the host is on the screen already.

    Each part both as written and percent-encoded, which is how `requests`
    renders a URL into a connection error.
    """
    from urllib.parse import parse_qsl, quote, unquote, urlsplit
    parts = urlsplit(url)
    pieces = [unquote(segment) for segment in parts.path.split("/")]
    pieces += [value for _, value in parse_qsl(parts.query,
                                               keep_blank_values=True)]
    pieces += [parts.username or "", parts.password or "",
               unquote(parts.fragment)]
    found = []
    for piece in pieces:
        if len(piece) >= _URL_PART_MIN:
            found += [piece, quote(piece, safe=""), quote(piece)]
    return found
