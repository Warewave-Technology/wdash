"""
The step language.

Nine verbs, chosen to cover the journeys people actually ask for — sign in,
add to basket, check out — and nothing else. Not a scripting language: the
agent never evaluates anything the user wrote. That is a deliberate limit and
it buys three things.

  * A step list can be RENDERED. A journey shows as seven rows with seven
    durations, which is what makes "it got slower at step 4" a sentence
    anybody can read. A script is one number.
  * Editing a monitor stops being remote code execution on every probe host.
    In a tool where twenty people share a configuration page that is not a
    theoretical distinction.
  * The failure names the step. "step 5 (expect_url): expected /dashboard, got
    /login" says the login silently failed. `TimeoutError: waiting for
    selector` says somebody has to go and read the script.

Pure. No Playwright import, no network, no clock. The agent turns these into
browser calls; this module only says what they mean.
"""

import re

#: How many steps a journey may have. Fifty is far past sign-in-and-checkout
#: and well short of a test suite — and a journey long enough to be a test
#: suite will hit its own timeout before anybody notices the limit.
MAX_STEPS = 50

#: Longest a single step may wait. A step that can block for five minutes
#: holds a browser open for five minutes, and the agent runs journeys one at a
#: time.
MAX_TIMEOUT_MS = 60_000
DEFAULT_TIMEOUT_MS = 10_000

#: `{{ secret.name }}` — the only interpolation there is. A journey that signs
#: in needs a password, and a password typed into the steps column is a
#: password in a database column, in a form field, and on a screen.
SECRET_PATTERN = re.compile(r"\{\{\s*secret\.([A-Za-z0-9_-]{1,64})\s*\}\}")


class StepError(ValueError):
    """A step the editor will not accept. The message is shown to the user."""


class Step:
    """One instruction. `selector` and `value` mean different things per kind.

    Deliberately not a dataclass with nine optional fields per verb: every
    step is at most a target and a value, and a shape that admits more grows
    a field per verb within a year.
    """

    __slots__ = ("kind", "selector", "value", "timeout_ms")

    def __init__(self, kind, selector="", value="", timeout_ms=None):
        self.kind = kind
        self.selector = selector or ""
        self.value = value or ""
        self.timeout_ms = timeout_ms

    def as_dict(self):
        out = {"kind": self.kind}
        if self.selector:
            out["selector"] = self.selector
        if self.value:
            out["value"] = self.value
        if self.timeout_ms:
            out["timeout_ms"] = self.timeout_ms
        return out

    @property
    def timeout(self):
        return self.timeout_ms or DEFAULT_TIMEOUT_MS

    def __repr__(self):
        return f"<Step {self.kind} {self.selector!r} {self.value!r}>"

    def __eq__(self, other):
        return (isinstance(other, Step) and self.as_dict() == other.as_dict())


class _Kind:
    """What one verb takes and what it is called on a page."""

    __slots__ = ("name", "label", "selector", "value", "value_label",
                 "asserts", "hint")

    def __init__(self, name, label, selector=False, value=False,
                 value_label="Value", asserts=False, hint=""):
        self.name = name
        self.label = label
        #: Does it need a CSS selector, and does it need a value?
        self.selector = selector
        self.value = value
        self.value_label = value_label
        #: An assertion checks something; an action changes something. The
        #: distinction is shown, because a journey made entirely of actions
        #: passes as long as the browser does not crash.
        self.asserts = asserts
        self.hint = hint


STEP_KINDS = {k.name: k for k in (
    _Kind("goto", "Go to", value=True, value_label="URL",
          hint="Opens a page. A journey has to start with one."),
    _Kind("click", "Click", selector=True,
          hint="Clicks the first matching element."),
    _Kind("fill", "Type into", selector=True, value=True, value_label="Text",
          hint="Clears the field first, then types. Use {{ secret.name }} "
               "for a password."),
    _Kind("select", "Choose from", selector=True, value=True,
          value_label="Option",
          hint="Picks an option in a <select> by its value."),
    _Kind("press", "Press key", selector=True, value=True, value_label="Key",
          hint="A key name — Enter, Tab, Escape. Some forms only submit "
               "on Enter."),
    _Kind("wait_for", "Wait for", selector=True,
          hint="Waits until the element appears. For a page that loads its "
               "content afterwards."),
    _Kind("expect_selector", "Expect element", selector=True, asserts=True,
          hint="Fails if the element is not there."),
    _Kind("expect_text", "Expect text", value=True, value_label="Text",
          asserts=True,
          hint="Fails unless the text is visible somewhere on the page."),
    _Kind("expect_no_text", "Expect no text", value=True, value_label="Text",
          asserts=True,
          hint="Fails if the text IS there. For the error banner that "
               "should not have appeared — a journey can reach the right "
               "page and still have failed."),
    _Kind("expect_url", "Expect URL", value=True, value_label="Contains",
          asserts=True,
          hint="Fails unless the address contains this. A login that "
               "silently fails leaves you on /login."),
)}


def parse(raw):
    """Turn stored or submitted JSON into a list of Step. Raises StepError.

    Validation is here rather than in the form because the agent reads the
    same rows: a journey stored by an older version, or edited through the
    API, has to fail on the server rather than halfway through a browser.
    """
    if raw is None:
        return []
    if isinstance(raw, (str, bytes)):
        import json
        try:
            raw = json.loads(raw or "[]")
        except ValueError as exc:
            raise StepError(f"The steps are not valid JSON: {exc}") from exc
    if not isinstance(raw, (list, tuple)):
        raise StepError("The steps have to be a list.")
    if len(raw) > MAX_STEPS:
        raise StepError(
            f"A journey can have at most {MAX_STEPS} steps; this one has "
            f"{len(raw)}.")

    steps = []
    for index, item in enumerate(raw, start=1):
        steps.append(_one(item, index))
    if not steps:
        raise StepError("A journey needs at least one step.")
    if steps[0].kind != "goto":
        # Without this the first step runs against `about:blank`, and the
        # failure is "element not found" — which sends somebody looking at
        # their selector when the journey never opened a page.
        raise StepError("A journey has to start by going to a URL.")
    if not any(STEP_KINDS[s.kind].asserts for s in steps):
        # A journey of nothing but clicks passes as long as the browser did
        # not crash. That is a check that reports success for a site serving
        # an error page, which is worse than no check at all.
        raise StepError(
            "A journey needs at least one expectation — otherwise it passes "
            "whatever the site shows.")
    return steps


def _one(item, index):
    where = f"Step {index}"
    if isinstance(item, Step):
        item = item.as_dict()
    if not isinstance(item, dict):
        raise StepError(f"{where} is not a step.")

    kind = (item.get("kind") or "").strip().lower()
    if kind not in STEP_KINDS:
        raise StepError(
            f"{where}: '{kind}' is not something a journey can do. "
            f"Available: {', '.join(sorted(STEP_KINDS))}.")
    spec = STEP_KINDS[kind]

    selector = (item.get("selector") or "").strip()
    value = item.get("value")
    value = value.strip() if isinstance(value, str) else ""

    if spec.selector and not selector:
        raise StepError(f"{where} ({spec.label.lower()}) needs an element to "
                        f"act on.")
    if spec.value and not value:
        raise StepError(f"{where} ({spec.label.lower()}) needs "
                        f"{spec.value_label.lower()}.")
    if not spec.selector and selector:
        raise StepError(f"{where} ({spec.label.lower()}) does not take an "
                        f"element.")

    if kind == "goto" and not value.startswith(("http://", "https://")):
        raise StepError(
            f"{where}: a URL has to begin http:// or https://. "
            f"A journey cannot open a file on the probe.")

    timeout = item.get("timeout_ms")
    if timeout in (None, ""):
        timeout = None
    else:
        try:
            timeout = int(timeout)
        except (TypeError, ValueError):
            raise StepError(f"{where}: the timeout has to be a number of "
                            f"milliseconds.") from None
        if not 100 <= timeout <= MAX_TIMEOUT_MS:
            raise StepError(
                f"{where}: the timeout has to be between 100ms and "
                f"{MAX_TIMEOUT_MS // 1000}s.")

    return Step(kind, selector, value, timeout)


def secret_names(steps):
    """Which secrets this journey refers to, in order of first appearance.

    Used by the editor to say which ones are missing BEFORE the journey runs
    and reports a login failure that was really a typo in a placeholder name.
    """
    seen = []
    for step in steps:
        for name in SECRET_PATTERN.findall(step.value or ""):
            if name not in seen:
                seen.append(name)
    return seen


def resolve(step, secrets):
    """This step's value with its placeholders filled in.

    Raises StepError naming the missing secret rather than typing
    `{{ secret.password }}` into the password box, which produces "wrong
    password" and sends somebody to check the account.
    """
    value = step.value or ""
    if "{{" not in value:
        return value

    missing = []

    def swap(match):
        name = match.group(1)
        if name not in (secrets or {}):
            missing.append(name)
            return ""
        return str(secrets[name])

    filled = SECRET_PATTERN.sub(swap, value)
    if missing:
        raise StepError(
            f"there is no secret called '{missing[0]}' on this journey")
    return filled


def describe(step):
    """One line, for a table. Never contains a secret's value.

    It cannot: it renders the placeholder, not the resolution. The redaction
    that matters happens in the agent's error messages; this side has nothing
    to redact because it never holds the secret in the first place.
    """
    spec = STEP_KINDS.get(step.kind)
    if spec is None:
        return step.kind
    parts = [spec.label]
    if spec.selector:
        parts.append(step.selector)
    if spec.value:
        parts.append(f'"{step.value}"' if spec.name != "goto" else step.value)
    return " ".join(parts)
