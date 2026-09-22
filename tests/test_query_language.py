"""
Neutral query language tests.

The syntax users type has not changed; what changed is the internal
representation. These tests protect two properties: that the familiar syntax
keeps working, and that the tree belongs to no backend.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from wdash.hub import query_language as ql  # noqa: E402
from wdash.hub.adapters import ElasticsearchLogSource  # noqa: E402


class ParseTest(unittest.TestCase):
    def test_empty_and_star_match_everything(self):
        for text in ("", "   ", "*", None):
            self.assertIsInstance(ql.parse(text), ql.MatchAll, repr(text))

    def test_field_equality(self):
        self.assertEqual(ql.parse("severity:ERROR"), ql.Term("severity", "ERROR"))

    def test_quoted_phrase(self):
        self.assertEqual(ql.parse('body:"database connection"'),
                         ql.Phrase("body", "database connection"))

    def test_prefix(self):
        self.assertEqual(ql.parse("service:payment*"), ql.Prefix("service", "payment"))

    def test_wildcard_in_the_middle(self):
        self.assertEqual(ql.parse("host:node-?-eu"), ql.Wildcard("host", "node-?-eu"))

    def test_exists(self):
        self.assertEqual(ql.parse("_exists_:trace_id"), ql.Exists("trace_id"))
        self.assertEqual(ql.parse("trace_id:*"), ql.Exists("trace_id"))

    def test_range(self):
        self.assertEqual(ql.parse("duration_ms:[100 TO 500]"),
                         ql.Range("duration_ms", gte=100, lte=500))
        self.assertEqual(ql.parse("duration_ms:[100 TO *]"),
                         ql.Range("duration_ms", gte=100, lte=None))

    def test_bare_term_is_full_text(self):
        self.assertEqual(ql.parse("timeout"), ql.FullText("timeout"))

    def test_numeric_values_are_coerced(self):
        self.assertEqual(ql.parse("http_status:500"), ql.Term("http_status", 500))
        self.assertIsInstance(ql.parse("http_status:500").value, int)


class BooleanTest(unittest.TestCase):
    def test_explicit_and(self):
        node = ql.parse("severity:ERROR AND service:api")
        self.assertIsInstance(node, ql.And)
        self.assertEqual(len(node.clauses), 2)

    def test_whitespace_is_implicit_and(self):
        """Whitespace means AND — the previous default_operator behaviour."""
        self.assertEqual(ql.parse("severity:ERROR service:api"),
                         ql.parse("severity:ERROR AND service:api"))

    def test_or(self):
        node = ql.parse("severity:ERROR OR severity:FATAL")
        self.assertIsInstance(node, ql.Or)

    def test_not_both_spellings(self):
        self.assertEqual(ql.parse("NOT severity:DEBUG"),
                         ql.parse("-severity:DEBUG"))

    def test_and_binds_tighter_than_or(self):
        node = ql.parse("a:1 OR b:2 AND c:3")
        self.assertIsInstance(node, ql.Or)
        self.assertIsInstance(node.clauses[1], ql.And)

    def test_parentheses_override_precedence(self):
        node = ql.parse("(a:1 OR b:2) AND c:3")
        self.assertIsInstance(node, ql.And)
        self.assertIsInstance(node.clauses[0], ql.Or)

    def test_nested_grouping(self):
        node = ql.parse("((a:1 OR b:2) AND NOT c:3) OR d:4")
        self.assertIsInstance(node, ql.Or)


class FieldAliasTest(unittest.TestCase):
    """Muscle memory must survive: users can keep typing `level:`."""

    def test_elasticsearch_names_map_to_neutral(self):
        self.assertEqual(ql.parse("level:ERROR"), ql.Term("severity", "ERROR"))
        self.assertEqual(ql.parse("message:foo"), ql.Term("body", "foo"))
        self.assertEqual(ql.parse("@timestamp:x"), ql.Term("timestamp", "x"))

    def test_neutral_names_work_too(self):
        self.assertEqual(ql.parse("severity:ERROR"), ql.parse("level:ERROR"))

    def test_alias_is_case_insensitive(self):
        self.assertEqual(ql.parse("LEVEL:ERROR"), ql.Term("severity", "ERROR"))

    def test_unknown_fields_pass_through(self):
        self.assertEqual(ql.parse("correlation_id:abc"),
                         ql.Term("correlation_id", "abc"))


class ErrorTest(unittest.TestCase):
    """Syntax errors must be caught before reaching Elasticsearch, with a message."""

    def test_missing_value(self):
        with self.assertRaises(ql.QueryError):
            ql.parse("severity:")

    def test_unclosed_parenthesis(self):
        with self.assertRaises(ql.QueryError):
            ql.parse("(severity:ERROR")

    def test_unexpected_closing_parenthesis(self):
        with self.assertRaises(ql.QueryError):
            ql.parse("severity:ERROR)")

    def test_bad_range_format(self):
        with self.assertRaises(ql.QueryError):
            ql.parse("duration_ms:[100 500]")

    def test_error_carries_position(self):
        try:
            ql.parse("(a:1")
        except ql.QueryError as exc:
            self.assertIsNotNone(exc.position)


class RoundTripTest(unittest.TestCase):
    def test_describe_reparses_to_the_same_tree(self):
        for text in ("severity:ERROR", 'body:"a b"', "service:pay*",
                     "NOT severity:DEBUG", "(a:1 OR b:2) AND c:3",
                     "_exists_:trace_id", "duration_ms:[1 TO 9]"):
            once = ql.parse(text)
            self.assertEqual(ql.parse(ql.describe(once)), once, text)


class ElasticsearchRenderTest(unittest.TestCase):
    """Rendering the tree to Elasticsearch. Raw text no longer passes through."""

    def setUp(self):
        self.source = ElasticsearchLogSource(None)

    def render(self, text):
        return self.source._render(ql.parse(text))

    @staticmethod
    def _fields(rendered):
        """Every backend field name a rendered clause mentions."""
        names = set()

        def walk(node):
            if isinstance(node, dict):
                for key, value in node.items():
                    if key in ("match", "match_phrase", "prefix", "wildcard",
                               "range"):
                        names.update(value.keys())
                    elif key == "exists":
                        names.add(value["field"])
                    else:
                        walk(value)
            elif isinstance(node, list):
                for item in node:
                    walk(item)

        walk(rendered)
        return names

    def test_neutral_field_names_become_elasticsearch_names(self):
        """One neutral name, every backend field it can live in.

        A search spans indices written by different pipelines: `severity` is
        `level` in a flat index and `severity_text` in one the OpenTelemetry
        Collector wrote. Naming only one matches nothing in the other half —
        silently, because "no results" and "wrong field" look identical.
        """
        severity = self._fields(self.render("severity:ERROR"))
        self.assertIn("level", severity)
        self.assertIn("severity_text", severity)

        body = self._fields(self.render('body:"x"'))
        self.assertIn("message", body)
        self.assertIn("body_text", body)

    def test_a_field_with_one_home_is_not_wrapped(self):
        """No should-clause where there is nothing to choose between.

        `timestamp` rather than `trace_id`, which used to be the example
        here and stopped being one: Serilog writes the trace under `@tr`,
        so a filter naming `trace_id` now has two places to look and is
        wrapped like every other neutral name. The rule this asserts is
        unchanged; the field that still demonstrates it is not.
        """
        self.assertEqual(self.render("timestamp:2026-09-22"),
                         {"match": {"@timestamp": {"query": "2026-09-22"}}})

    def test_and_the_trace_is_looked_for_where_serilog_puts_it(self):
        """The other half of the change above, so that moving the example
        did not quietly drop what moved it."""
        fields = self._fields(self.render("trace_id:abc"))
        self.assertIn("trace_id", fields)
        self.assertIn("@tr", fields)

    def test_term_uses_match_not_term(self):
        """`term` silently matches nothing on analysed fields."""
        rendered = str(self.render("service:api"))
        self.assertIn("match", rendered)
        self.assertNotIn("'term'", rendered)

    def test_boolean_structure(self):
        rendered = self.render("a:1 OR b:2")
        self.assertEqual(rendered["bool"]["minimum_should_match"], 1)
        self.assertEqual(len(rendered["bool"]["should"]), 2)

    def test_not_becomes_must_not(self):
        self.assertIn("must_not", self.render("NOT severity:DEBUG")["bool"])

    def test_no_raw_query_string_is_emitted(self):
        """Emitting query_string would tie the query language back to Elasticsearch."""
        import json
        for text in ("severity:ERROR AND service:pay*", "(a:1 OR b:2)",
                     "_exists_:trace_id", "free text"):
            self.assertNotIn("query_string", json.dumps(self.render(text)), text)

    def test_exists_and_range(self):
        self.assertEqual(self.render("_exists_:timestamp"),
                         {"exists": {"field": "@timestamp"}})
        # A name the field table does not know is also tried where the
        # collector keeps it — under resource.attributes. and attributes.
        # This pinned the one field, which is where a collector record does
        # not have it.
        self.assertEqual(self.render("duration_ms:[1 TO 9]"), {"bool": {
            "should": [{"range": {name: {"gte": 1, "lte": 9}}}
                       for name in ("duration_ms", "resource.attributes.duration_ms",
                                    "attributes.duration_ms")],
            "minimum_should_match": 1}})


if __name__ == "__main__":
    unittest.main(verbosity=2)
