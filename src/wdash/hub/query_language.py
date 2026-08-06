"""
Neutral query language.

Why we parse
------------
The text a user types — `level:ERROR AND service:payment*` — is Elasticsearch
`query_string` syntax. Passing it through untouched would bind the query
language to Elasticsearch too: a second backend could not parse it.

The answer is not to CHANGE the user-facing syntax; people know it. The answer
is to parse the text into a neutral tree and let each adapter render it into
its own language.

Side benefit
------------
Raw text is no longer injected into Elasticsearch; what we emit is query DSL.
That lets us catch syntax errors before the query leaves the process (with a
better message) and decide ourselves which clauses belong in filter context.

Supported syntax
----------------
    *                        everything
    level:ERROR              field equality
    message:"exact phrase"   quoted phrase
    service:payment*         prefix
    status:[200 TO 299]      range
    _exists_:trace_id        field is present
    a AND b, a OR b, a b     combination (whitespace means AND)
    NOT a, -a                negation
    (a OR b) AND c           grouping
    free text                searched in the default field
"""

import re
from dataclasses import dataclass, field
from typing import Any, Optional, Tuple

# Maps the names users familiar with Elasticsearch/ECS type onto their neutral
# equivalents. `level:ERROR` keeps working; internally it becomes `severity`.
FIELD_ALIASES = {
    "level": "severity",
    "loglevel": "severity",
    "log_level": "severity",
    "message": "body",
    "msg": "body",
    "@timestamp": "timestamp",
    "time": "timestamp",
}

#: Field that bare terms are searched in
DEFAULT_FIELD = "body"


class QueryError(ValueError):
    """The query could not be parsed. The message must be user-presentable."""

    def __init__(self, message, position=None):
        self.position = position
        super().__init__(message if position is None
                         else f"{message} (position {position})")


# --------------------------------------------------------------------------
# Tree nodes
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class MatchAll:
    pass


@dataclass(frozen=True)
class Term:
    """Field equals a value. Matched through analysis on text fields."""
    field: str
    value: Any


@dataclass(frozen=True)
class Phrase:
    field: str
    text: str


@dataclass(frozen=True)
class Prefix:
    field: str
    value: str


@dataclass(frozen=True)
class Wildcard:
    field: str
    pattern: str


@dataclass(frozen=True)
class Range:
    field: str
    gte: Optional[Any] = None
    lte: Optional[Any] = None
    gt: Optional[Any] = None
    lt: Optional[Any] = None


@dataclass(frozen=True)
class Exists:
    field: str


@dataclass(frozen=True)
class FullText:
    """Free text with no field name."""
    text: str


@dataclass(frozen=True)
class And:
    clauses: Tuple = field(default_factory=tuple)


@dataclass(frozen=True)
class Or:
    clauses: Tuple = field(default_factory=tuple)


@dataclass(frozen=True)
class Not:
    clause: Any


# --------------------------------------------------------------------------
# Tokenising
# --------------------------------------------------------------------------

_TOKEN_RE = re.compile(r"""
    (?P<space>\s+)
  | (?P<lparen>\()
  | (?P<rparen>\))
  | (?P<quoted>"(?:[^"\\]|\\.)*")
  | (?P<bracket>\[[^\]]*\])
  | (?P<colon>:)
  | (?P<minus>-(?=\S))
  | (?P<word>[^\s():"]+)
""", re.VERBOSE)

_KEYWORDS = {"AND", "OR", "NOT"}


def _tokenise(text):
    tokens, pos = [], 0
    while pos < len(text):
        match = _TOKEN_RE.match(text, pos)
        if not match:
            raise QueryError(f"Unrecognised character: {text[pos]!r}", pos)
        kind = match.lastgroup
        if kind != "space":
            tokens.append((kind, match.group(), pos))
        pos = match.end()
    return tokens


# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------

class _Parser:
    def __init__(self, tokens):
        self.tokens = tokens
        self.i = 0

    def peek(self):
        return self.tokens[self.i] if self.i < len(self.tokens) else None

    def next(self):
        token = self.peek()
        if token:
            self.i += 1
        return token

    def at_keyword(self, word):
        token = self.peek()
        return token and token[0] == "word" and token[1].upper() == word

    # or := and (OR and)*
    def parse_or(self):
        clauses = [self.parse_and()]
        while self.at_keyword("OR"):
            self.next()
            clauses.append(self.parse_and())
        return clauses[0] if len(clauses) == 1 else Or(tuple(clauses))

    # and := not (AND? not)*   -- whitespace is an implicit AND
    def parse_and(self):
        clauses = [self.parse_not()]
        while True:
            token = self.peek()
            if token is None or token[0] == "rparen" or self.at_keyword("OR"):
                break
            if self.at_keyword("AND"):
                self.next()
            clauses.append(self.parse_not())
        return clauses[0] if len(clauses) == 1 else And(tuple(clauses))

    def parse_not(self):
        if self.at_keyword("NOT"):
            self.next()
            return Not(self.parse_not())
        token = self.peek()
        if token and token[0] == "minus":
            self.next()
            return Not(self.parse_not())
        return self.parse_primary()

    def parse_primary(self):
        token = self.next()
        if token is None:
            raise QueryError("Query ended unexpectedly")

        kind, value, pos = token

        if kind == "lparen":
            inner = self.parse_or()
            closing = self.next()
            if not closing or closing[0] != "rparen":
                raise QueryError("Unclosed parenthesis", pos)
            return inner

        if kind == "rparen":
            raise QueryError("Unexpected ')'", pos)

        if kind == "quoted":
            return Phrase(DEFAULT_FIELD, _unquote(value))

        if kind == "word":
            if value == "*":
                return MatchAll()
            nxt = self.peek()
            if nxt and nxt[0] == "colon":
                self.next()
                return self._parse_field(value, pos)
            return FullText(value)

        raise QueryError(f"Unexpected token: {value!r}", pos)

    def _parse_field(self, name, pos):
        token = self.next()
        if token is None:
            raise QueryError(f"'{name}:' expects a value", pos)

        kind, raw, tpos = token
        neutral = normalise_field(name)

        if kind == "quoted":
            return Phrase(neutral, _unquote(raw))
        if kind == "bracket":
            return _parse_range(neutral, raw, tpos)
        if kind != "word":
            raise QueryError(f"'{name}:' received an invalid value", tpos)

        # _exists_:field
        if name == "_exists_":
            return Exists(normalise_field(raw))
        if raw == "*":
            return Exists(neutral)
        if raw.endswith("*") and "*" not in raw[:-1] and "?" not in raw:
            return Prefix(neutral, raw[:-1])
        if "*" in raw or "?" in raw:
            return Wildcard(neutral, raw)
        return Term(neutral, _coerce(raw))


def _unquote(text):
    return text[1:-1].replace('\\"', '"').replace("\\\\", "\\")


def _coerce(raw):
    """Convert numeric-looking values to numbers, for ranges and equality."""
    try:
        return int(raw)
    except ValueError:
        pass
    try:
        return float(raw)
    except ValueError:
        return raw


_RANGE_RE = re.compile(r"^\[\s*(\S+)\s+TO\s+(\S+)\s*\]$", re.IGNORECASE)


def _parse_range(field_name, raw, pos):
    match = _RANGE_RE.match(raw)
    if not match:
        raise QueryError(f"Malformed range: {raw!r}. Expected [low TO high]", pos)
    low, high = match.groups()
    return Range(field_name,
                 gte=None if low == "*" else _coerce(low),
                 lte=None if high == "*" else _coerce(high))


def normalise_field(name):
    """Translate the field name the user typed into its neutral equivalent."""
    return FIELD_ALIASES.get(name.lower(), name)


def parse(text):
    """Parse query text into the neutral tree. Empty or `*` yields MatchAll."""
    if text is None:
        return MatchAll()
    text = text.strip()
    if not text or text == "*":
        return MatchAll()

    tokens = _tokenise(text)
    if not tokens:
        return MatchAll()

    parser = _Parser(tokens)
    node = parser.parse_or()
    leftover = parser.peek()
    if leftover:
        raise QueryError(f"Unexpected token: {leftover[1]!r}", leftover[2])
    return node


def describe(node):
    """Render the tree back to readable text. For debugging and tests."""
    if isinstance(node, MatchAll):
        return "*"
    if isinstance(node, Term):
        return f"{node.field}:{node.value}"
    if isinstance(node, Phrase):
        return f'{node.field}:"{node.text}"'
    if isinstance(node, Prefix):
        return f"{node.field}:{node.value}*"
    if isinstance(node, Wildcard):
        return f"{node.field}:{node.pattern}"
    if isinstance(node, Exists):
        return f"_exists_:{node.field}"
    if isinstance(node, Range):
        low = "*" if node.gte is None else node.gte
        high = "*" if node.lte is None else node.lte
        return f"{node.field}:[{low} TO {high}]"
    if isinstance(node, FullText):
        return node.text
    if isinstance(node, Not):
        return f"NOT {describe(node.clause)}"
    if isinstance(node, And):
        return "(" + " AND ".join(describe(c) for c in node.clauses) + ")"
    if isinstance(node, Or):
        return "(" + " OR ".join(describe(c) for c in node.clauses) + ")"
    return "?"
