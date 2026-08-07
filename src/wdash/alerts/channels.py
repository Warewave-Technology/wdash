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
    headers.update((secrets or {}).get("headers") or {})

    import requests
    client = session or requests
    try:
        response = client.post(url, timeout=TIMEOUT, headers=headers,
                               data=json.dumps(body))
    except Exception as exc:
        raise DeliveryError(_redact(str(exc), url, headers)) from exc

    if response.status_code >= 400:
        # The body, trimmed. A webhook that refuses usually says why — "no
        # such channel", "token revoked" — and that sentence is the whole
        # answer to why alerts stopped arriving.
        detail = (response.text or "")[:300].strip()
        raise DeliveryError(
            _redact(f"the receiver answered {response.status_code}"
                    f"{': ' + detail if detail else ''}", url, headers))
    return response.status_code


def _redact(text, url, headers):
    """Keep the credential out of the stored error.

    The failure is written to the alert history and shown on a screen. A
    webhook URL is itself a secret for Slack and Teams — the path IS the
    credential — so it never appears in a message.
    """
    text = str(text)
    if url:
        # The last path segment, wherever it appears — in a whole URL echoed
        # back by the receiver, or in the host-and-path form `requests`
        # renders into a connection error. That is where the credential lives
        # for Slack, Teams and every webhook shaped like them.
        #
        # There WAS a second line replacing the whole URL as well. It could
        # not be made to fail: every message that contains the URL contains
        # the tail, so this rule had already redacted it. Untestable
        # redundancy is the thing somebody edits next while believing it does
        # something.
        #
        # The length guard keeps a short path — `/hook`, `/alerts` — from
        # blanking out ordinary words in the message. A path that short is not
        # a credential.
        tail = url.rsplit("/", 1)[-1]
        if len(tail) > 8:
            text = text.replace(tail, "***")
    for name, value in (headers or {}).items():
        if name.lower() in ("authorization", "x-api-key", "cookie") and value:
            text = text.replace(str(value), "***")
    return text
