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


def matches_any(patterns, name):
    """Deny wins. An exclusion with no inclusion grants nothing."""
    allow, deny = partition(patterns)
    if any(matches(pattern, name) for pattern in deny):
        return False
    return any(matches(pattern, name) for pattern in allow)


#: Separator for a source-qualified pattern: `es-logs:app-*`.
QUALIFIER = ":"


def split_qualifier(pattern):
    """Return (source_or_None, pattern).

    A bare pattern keeps meaning exactly what it always did — every source —
    so no existing role changes behaviour. Qualifying is opt-in precision for
    deployments where "app-* everywhere" is too much.

    A container name containing a colon is not a thing in Elasticsearch or
    Loki, so the separator is unambiguous in practice; if that ever stops being
    true this is the one place that has to change.
    """
    if QUALIFIER not in (pattern or ""):
        return None, pattern
    source, _, rest = pattern.partition(QUALIFIER)
    if not source or not rest:
        return None, pattern
    return source, rest


def matches_for_source(patterns, name, source_name=None):
    """Does `name` satisfy the rules, given which source it came from?

    A qualified pattern applies only to its named source; a bare one applies
    everywhere. With no source given, qualified patterns are ignored rather
    than assumed to match — the fail-closed direction.

    Denials are evaluated first and completely: `-*-pii-*` blocks a name even
    if three other patterns allow it. Any other order would make the meaning
    of a rule depend on where somebody happened to type it.
    """
    allowed = False
    for pattern in patterns or ():
        is_denial, rest = split_deny(pattern)
        qualifier, bare = split_qualifier(rest)
        if qualifier is not None:
            if source_name is None or qualifier != source_name:
                continue
        if not matches(bare, name):
            continue
        if is_denial:
            return False
        allowed = True
    return allowed
