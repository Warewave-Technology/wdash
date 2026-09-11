"""
One pattern language.

There used to be two, both called "index patterns". `Scope.allows_container`
understood a trailing star only; the Elasticsearch adapter also understood
leading and surrounding ones. So `*logs*` written into a role matched nothing —
silently, while the same string in a source configuration worked.

That failed closed, so it was not a hole. It was worse in a different way: an
administrator writing a pattern that works everywhere else got no access and no
error, and nothing in the product said why.

Supported forms, and there are only four:

    *            everything
    prefix*      starts with
    *suffix      ends with
    *middle*     contains

Anything else is an exact name. Regular expressions are deliberately absent:
this is a boundary people write under time pressure, and a language where a
typo silently widens access is the wrong language for that.

Exclusions
----------
A leading `-` means "never this", and an exclusion beats every inclusion:

    app-*        everything in the app family
    -*-pii-*     …except anything holding personal data

This exists because a pattern is a standing rule over a changing world.
`app-*` says nothing about what it will match when `app-billing-pii-000001` is
created tomorrow, and nobody will have touched the role. Writing the intent —
"the app family, but never the sensitive ones" — is safe by construction in a
way that any snapshot of today's containers is not.

Order matters and only one order is safe: deny wins. A list of exclusions with
no inclusion grants nothing, which is the same fail-closed rule as an empty
list.
"""

#: Marks a pattern as a denial. Chosen to match Elasticsearch's own index
#: exclusion syntax, so it reads the way people already expect.
DENY = "-"


def matches(pattern, name):
    """Does `name` satisfy `pattern`?"""
    if not pattern:
        return False
    if pattern == "*":
        return True

    leading = pattern.startswith("*")
    trailing = pattern.endswith("*")

    if leading and trailing:
        return pattern[1:-1] in name
    if trailing:
        return name.startswith(pattern[:-1])
    if leading:
        return name.endswith(pattern[1:])
    return pattern == name


def split_deny(pattern):
    """Return (is_denial, pattern_without_the_marker)."""
    pattern = (pattern or "").strip()
    if pattern.startswith(DENY) and len(pattern) > 1:
        return True, pattern[1:]
    return False, pattern


def partition(patterns):
    """Split a list into (allow, deny), each with the marker stripped."""
    allow, deny = [], []
    for pattern in patterns or ():
        is_denial, bare = split_deny(pattern)
        (deny if is_denial else allow).append(bare)
    return allow, deny


#: What kind of pattern this is. Adapters render each shape into their own
#: query language; deciding the shape is the LANGUAGE's job, not theirs, or
#: every adapter re-derives it and one of them gets a form wrong.
ANY = "any"
PREFIX = "prefix"
SUFFIX = "suffix"
CONTAINS = "contains"
EXACT = "exact"


def shape(pattern):
    """Classify a pattern (with any deny marker already stripped)."""
    if pattern == "*":
        return ANY
    leading, trailing = pattern.startswith("*"), pattern.endswith("*")
    if leading and trailing:
        return CONTAINS
    if trailing:
        return PREFIX
    if leading:
        return SUFFIX
    return EXACT


def glob(pattern, literal):
    """The pattern for a backend whose own glob reads more characters.

    Only a leading and a trailing star are wildcards here, so the text
    between them is passed through `literal`, which makes it mean itself in
    the backend's syntax.
    """
    kind = shape(pattern)
    if kind == ANY:
        return pattern
    leading = kind in (SUFFIX, CONTAINS)
    trailing = kind in (PREFIX, CONTAINS)
    core = pattern[1 if leading else 0:len(pattern) - 1 if trailing else None]
    return ("*" if leading else "") + literal(core) + ("*" if trailing else "")


def matches_any(patterns, name):
    """Deny wins. An exclusion with no inclusion grants nothing."""
    allow, deny = partition(patterns)
    if any(matches(pattern, name) for pattern in deny):
        return False
    return any(matches(pattern, name) for pattern in allow)


#: Separator for a source-qualified pattern: `es-logs:app-*`.
QUALIFIER = ":"


def split_qualifier(pattern):
    """Return (source_or_None, pattern), splitting at the first colon.

    A bare pattern keeps meaning exactly what it always did — every source —
    so no existing role changes behaviour. Qualifying is opt-in precision for
    deployments where "app-* everywhere" is too much.

    This is only the split. Whether the part before the colon IS a qualifier
    depends on whether a source has that name — see `parse`.
    """
    if QUALIFIER not in (pattern or ""):
        return None, pattern
    source, _, rest = pattern.partition(QUALIFIER)
    if not source or not rest:
        return None, pattern
    return source, rest


def parse(pattern, sources=None):
    """Return (is_denial, source_or_None, bare) — the one reading of a rule.

    The part before the first colon qualifies the rule only when a source
    has that name (`sources`, the configured names; None reads every colon
    as a qualifier, for callers that do not know them). Names have colons:
    OpenTelemetry's default service name is `unknown_service:java`, and
    Loki's labels and service names take them too. Read as a qualifier,
    `unknown_service:java` granted a service in a source called
    `unknown_service` — nothing — and `*` with `-unknown_service:*` hid
    nothing. A colon that names no source is part of the name, and a rule
    that does not mention a real source never changes meaning.

    The marker may come before the qualifier or after it: `-primary:secret-*`
    and `primary:-secret-*` are the same exclusion. Read the second way as a
    grant, it named things starting with "-secret-", which nothing is called,
    and every reader of the rule had to agree on that or the query pushed to a
    backend and the check applied to its answer meant different things.
    """
    is_denial, rest = split_deny(pattern)
    qualifier, bare = split_qualifier(rest)
    if qualifier is not None and sources is not None and qualifier not in sources:
        return is_denial, None, rest
    if qualifier is not None:
        inner_denial, bare = split_deny(bare)
        is_denial = is_denial or inner_denial
    return is_denial, qualifier, bare


def for_source(patterns, source_name, sources=None):
    """The patterns that apply to one source, with their qualifiers removed.

    For an adapter pushing a boundary into its backend's own query language:
    it knows which source it is, so a pattern qualified for another source
    says nothing about it, and one qualified for this source is an ordinary
    pattern here. A denial keeps its marker, so `partition` still sees it.
    """
    applicable = []
    for pattern in patterns or ():
        is_denial, qualifier, bare = parse(pattern, sources)
        if qualifier is not None and qualifier != source_name:
            continue
        applicable.append((DENY if is_denial else "") + bare)
    return applicable


def narrows(patterns, source_name, sources=None):
    """Whether these rules hide anything in this source. None hides nothing.

    A `*` that applies here grants everything, so only an exclusion beside
    it narrows. Asking whether `*` was in the list, or whether the list was
    anything but `*`, got one of those two cases wrong each time.
    """
    if patterns is None:
        return False
    allow, deny = partition(for_source(patterns, source_name, sources))
    return bool(deny) or "*" not in allow


def matches_for_source(patterns, name, source_name=None, sources=None):
    """Does `name` satisfy the rules, given which source it came from?

    A qualified pattern applies only to its named source; a bare one applies
    everywhere.

    With no source given, the answer has to hold whichever source the name
    came from — and the two kinds of rule fail closed in opposite
    directions. A qualified GRANT is ignored: it cannot be shown to apply. A
    qualified DENIAL is honoured: it cannot be shown NOT to. Ignoring both,
    which is what this did, made every source-less check fail open: a role of
    `*` with `-primary:secret-*` was refused `secret-1` by the search and
    handed it by the record, raw and context views, which asked without one.

    Denials are evaluated first and completely: `-*-pii-*` blocks a name even
    if three other patterns allow it. Any other order would make the meaning
    of a rule depend on where somebody happened to type it.
    """
    allowed = False
    for pattern in patterns or ():
        is_denial, qualifier, bare = parse(pattern, sources)
        if qualifier is not None and qualifier != source_name:
            if source_name is None and is_denial and matches(bare, name):
                return False
            continue
        if not matches(bare, name):
            continue
        if is_denial:
            return False
        allowed = True
    return allowed
