"""
A search over more indices than fit in a URL.

Elasticsearch takes the index names in the PATH — `GET /a,b,c,…/_search` —
and `http.max_initial_line_length` defaults to 4kb. A cluster with a few
hundred indices blows that on the first search. Measured against a real one
with 563 of them, the request line came to 19,039 characters and every
search failed with

    BadRequestError(400, 'too_long_http_line_exception',
                    'An HTTP line is larger than 4096 bytes.')

on a screen that had just said "Available: 563 indices". The message names
the transport and not the cause, and there is nothing a reader can do with
it — which is why this is a fault in WDash rather than a fact about
Elasticsearch.

The fix is the transport: past a threshold the same search goes as a
one-request `_msearch`, which carries the index list in the body. The limit
is on the request line, so moving the names off it is the whole of it.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from wdash.hub.adapters.elasticsearch import (  # noqa: E402
    MAX_INDICES_IN_URL, _in_url_sized_batches, _search,
)

BODY = {"query": {"match_all": {}}, "size": 1}
ONE_HIT = {"hits": {"total": {"value": 1}, "hits": []}}


def _names(count, width=34):
    """Index names of the width a real one has.

    `filebeat-8.19.9-2026.09.22-000123` is 33 characters, which is what made
    563 of them nineteen thousand.
    """
    return [f"filebeat-8.19.9-2026.09.22-{index:06d}".ljust(width, "x")
            for index in range(count)]


class _Recording:
    """An Elasticsearch client that remembers which door was used."""

    def __init__(self, answer=None, responses=None):
        self.searched = []
        self.msearched = []
        self._answer = answer or ONE_HIT
        self._responses = responses

    def search(self, index=None, **kwargs):
        self.searched.append(index)
        return self._answer

    def msearch(self, searches=None, **kwargs):
        self.msearched.append(searches)
        if self._responses is not None:
            return {"responses": self._responses}
        return {"responses": [self._answer]}


class WhichTransportTest(unittest.TestCase):
    def test_a_short_list_still_goes_in_the_url(self):
        """The ordinary case, and it must not move. `_msearch` answers a
        per-query failure inside a 200 where `search` raises, so routing
        everything through it would change how every error surfaces."""
        client = _Recording()
        _search(client, _names(5), BODY)
        self.assertEqual(len(client.searched), 1)
        self.assertEqual(client.msearched, [])

    def test_a_list_too_long_for_a_url_goes_in_the_body(self):
        client = _Recording()
        _search(client, _names(563), BODY)
        self.assertEqual(client.searched, [])
        self.assertEqual(len(client.msearched), 1)

    def test_the_threshold_leaves_room_for_the_rest_of_the_line(self):
        """The line also carries the verb, `/_search`, the query string and
        `HTTP/1.1`. A threshold set at Elasticsearch's own 4,096 would send
        a request line over the limit and fail in exactly the way this
        exists to prevent."""
        self.assertLess(MAX_INDICES_IN_URL, 4096)
        self.assertGreater(MAX_INDICES_IN_URL, 2000,
                           "so low that ordinary clusters take the slow door")

    def test_it_switches_on_the_length_and_not_on_the_count(self):
        """Ten indices with very long names are the same problem as five
        hundred with short ones. Counting them would answer the wrong
        question."""
        client = _Recording()
        _search(client, [("a" * 900) for _ in range(5)], BODY)
        self.assertEqual(client.searched, [])
        self.assertEqual(len(client.msearched), 1)

    def test_a_string_of_indices_is_measured_too(self):
        """Callers pass a list or an already-joined string, and the string
        form used to skip the join — and would have skipped the check with
        it."""
        client = _Recording()
        _search(client, ",".join(_names(563)), BODY)
        self.assertEqual(client.searched, [])
        self.assertEqual(len(client.msearched), 1)


class WhatComesBackTest(unittest.TestCase):
    """Both doors have to answer in the same shape. No caller knows which
    one it got."""

    def test_the_answer_is_unwrapped(self):
        client = _Recording(answer={"hits": {"total": {"value": 7},
                                             "hits": []}})
        got = _search(client, _names(563), BODY)
        self.assertEqual(got["hits"]["total"]["value"], 7)

    def test_the_index_list_reaches_the_body(self):
        client = _Recording()
        _search(client, _names(563), BODY)
        header, sent = client.msearched[0]
        self.assertIn("filebeat-8.19.9-2026.09.22-000000", header["index"])
        self.assertEqual(sent, BODY)

    def test_a_failure_inside_a_200_is_raised(self):
        """`_msearch` reports a per-query error in the response body and
        answers 200; `search` raises. Passing the first through would hand
        every caller a dict with no `hits` and no exception, which is a
        search that silently returned nothing."""
        client = _Recording(responses=[{"error": {"type": "index_not_found"}}])
        with self.assertRaises(Exception) as caught:
            _search(client, _names(563), BODY)
        self.assertIn("index_not_found", str(caught.exception))

    def test_an_empty_answer_says_what_happened(self):
        """`assertRaises(Exception)` was the first version and it passed
        with the guard deleted — `answers[0]` on an empty list raises
        IndexError, which is an Exception. What the guard buys is a sentence
        naming the search that got nothing back, so that is what is asserted.
        """
        client = _Recording(responses=[])
        with self.assertRaises(Exception) as caught:
            _search(client, _names(563), BODY)
        self.assertNotIsInstance(caught.exception, IndexError)
        self.assertIn("563", str(caught.exception))


class TheMappingRequestTest(unittest.TestCase):
    """The path the fix above missed.

    Reported from the same cluster, after the `_msearch` fix shipped: the
    results arrived — 177,511 of them over 710 indices — and the field
    statistics beside them still read

        elasticsearch could not answer: too_long_http_line_exception

    `indices.get_mapping` has nowhere else to put the names. The index IS
    the path, there is no body to move them into, so the only way under the
    limit is fewer names per call and more calls. Measured against the lab
    with the reported cluster's 710: 21,205 characters joined, one call
    refused, seven batches answered.

    Fixing the path somebody reports and not the others is how one fault
    becomes two, which is why the class below walks the client for any
    call that still puts a list in a URL.
    """

    def test_a_list_that_fits_is_one_batch(self):
        """The ordinary cluster, which must keep making one request."""
        self.assertEqual(list(_in_url_sized_batches(_names(5))),
                         [_names(5)])

    def test_nothing_at_all_is_no_batches(self):
        """Not one empty batch: `",".join([])` is the empty string, and
        `get_mapping(index="")` asks about every index in the cluster."""
        self.assertEqual(list(_in_url_sized_batches([])), [])

    def test_every_batch_fits_in_a_request_line(self):
        batches = list(_in_url_sized_batches(_names(710)))
        self.assertGreater(len(batches), 1)
        for batch in batches:
            self.assertLessEqual(len(",".join(batch)), MAX_INDICES_IN_URL)

    def test_and_between_them_they_hold_every_index(self):
        """A batching that loses names is worse than the fault: the panel
        answers, and answers about part of the cluster without saying so."""
        names = _names(710)
        self.assertEqual([n for batch in _in_url_sized_batches(names)
                          for n in batch], names)

    def test_it_counts_the_commas_that_join_them(self):
        """709 separators is 709 characters of the line. A batcher that
        measured only the names would build batches that just overflow, and
        the failure would come back at a cluster size nothing tested."""
        wide = "x" * (MAX_INDICES_IN_URL // 2)
        self.assertEqual(len(list(_in_url_sized_batches([wide, wide]))), 2)

    def test_a_single_name_too_long_for_the_line_still_goes(self):
        """It cannot fit and there is no smaller batch than one. Dropping it
        would be a silent hole; sending it is a 400 that names the index."""
        huge = "y" * (MAX_INDICES_IN_URL + 10)
        self.assertEqual(list(_in_url_sized_batches([huge])), [[huge]])


class NoCallLeavesTheNamesInTheUrlTest(unittest.TestCase):
    """The sweep, rather than waiting for the next report of the same fault.

    Two calls in the adapter take an index list and only one of them was
    fixed, so the screen that showed results also showed a failure. This
    drives a source over the reported cluster's 710 indices and lets the
    cluster refuse what a real one refuses — which is the only way to find
    the third such call before somebody else does.
    """

    #: Elasticsearch's `http.max_initial_line_length`, and 40 characters for
    #: the verb, the path around the names, the query string and `HTTP/1.1`.
    LINE_LIMIT = 4096
    AROUND_THE_NAMES = 40

    def cluster(self, count=710):
        from tests.support import ModelledES

        limit, overhead = self.LINE_LIMIT, self.AROUND_THE_NAMES

        class Strict(ModelledES):
            """A cluster that refuses a request line over the limit.

            `ModelledES` answers whatever it is asked, which is what makes
            it useful everywhere else and useless here: the fault IS the
            refusal.
            """

            def __init__(self, indices):
                super().__init__(indices)
                self.refused = []
                self._in_a_body = False

            def _check(self, index):
                # Not while answering an `_msearch`: `ModelledES` runs one by
                # calling its own `search` per query, and a real cluster has
                # already read those names out of the body by then. Checking
                # them would fail the very door this exists to prove.
                if self._in_a_body:
                    return
                if len(str(index or "")) + overhead > limit:
                    self.refused.append(str(index)[:60])
                    raise RuntimeError(
                        "too_long_http_line_exception: An HTTP line is "
                        f"larger than {limit} bytes.")

            def search(self, index=None, **kwargs):
                self._check(index)
                return super().search(index=index, **kwargs)

            def msearch(self, searches=None, **kw):
                self._in_a_body = True
                try:
                    return super().msearch(searches=searches, **kw)
                finally:
                    self._in_a_body = False

            @property
            def indices(self):
                outer, inner = self, super().indices

                class Indices:
                    def get_mapping(self, index=None, **kw):
                        outer._check(index)
                        return inner.get_mapping(index=index, **kw)
                return Indices()

        mapping = {"@timestamp": {"type": "date"},
                   "message": {"type": "text"},
                   "level": {"type": "keyword"},
                   "service": {"type": "keyword"}}
        #: On the FIRST index only, so a batching that keeps the last answer
        #: and discards the others loses it. Every batch's mapping has to be
        #: merged into one, and a cluster whose indices all say the same
        #: thing cannot tell the difference.
        first = dict(mapping, tenant={"type": "keyword"})
        # A fresh document per index: `ModelledES` pops `_id` out of the one
        # it is handed, so a shared dict is read once and empty 709 times.
        def document():
            return [{"_id": "a", "@timestamp": "2026-08-04T09:30:00Z",
                     "message": "hello", "level": "INFO", "service": "svc",
                     "tenant": "north"}]

        names = _names(count)
        return Strict({name: (first if name == names[0] else mapping,
                              document())
                       for name in names})

    def drive(self):
        """Every call a person makes by opening the logs page once."""
        import datetime

        from wdash.hub import LogQuery, Scope, TimeWindow
        from wdash.hub.adapters import ElasticsearchLogSource
        from wdash.hub.query import DEFAULT_LOG_FIELDS

        es = self.cluster()
        source = ElasticsearchLogSource(es, name="many",
                                        patterns=("filebeat-*",))
        window = TimeWindow.exact(
            datetime.datetime(2026, 8, 4, 9, tzinfo=datetime.timezone.utc),
            datetime.datetime(2026, 8, 4, 10, tzinfo=datetime.timezone.utc))
        every = Scope.unrestricted()
        query = LogQuery(window=window, limit=10, fields=DEFAULT_LOG_FIELDS)
        return es, {
            "search": lambda: source.search(query, every),
            "the field statistics beside it": lambda: source.field_stats(
                LogQuery(window=window), every),
            "the histogram above it": lambda: source.histogram(
                LogQuery(window=window), every),
            "the fields a panel can group by": lambda: source.group_by_fields(
                every),
        }

    def test_the_cluster_really_would_refuse_the_whole_list(self):
        """Without this the tests below pass against a model that took the
        long line happily, which is what a model does by default."""
        es = self.cluster()
        with self.assertRaises(RuntimeError) as caught:
            es.indices.get_mapping(index=",".join(_names(710)))
        self.assertIn("too_long_http_line", str(caught.exception))

    def test_and_nothing_the_logs_page_does_is_refused(self):
        es, calls = self.drive()
        for what, call in calls.items():
            with self.subTest(what=what):
                call()
        self.assertEqual(es.refused, [])

    def test_the_search_still_finds_the_records(self):
        """A batching that answers by asking about fewer indices is the
        worse bug: the page fills, and says nothing about the rest of the
        cluster."""
        _, calls = self.drive()
        self.assertEqual(len(calls["search"]().records), 10)

    def test_and_the_field_statistics_still_have_fields(self):
        _, calls = self.drive()
        stats = calls["the field statistics beside it"]()
        fields = stats.fields if hasattr(stats, "fields") else stats
        self.assertTrue(fields, "answered, but about nothing")

    def test_every_batchs_mapping_is_kept_and_not_just_the_last(self):
        """One request became several, and several answers have to be merged
        into the one the single request used to give. Keeping the last is a
        panel that answers about the tail of the cluster — with no warning,
        because a field that is missing looks exactly like a field nothing
        has."""
        _, calls = self.drive()
        stats = calls["the field statistics beside it"]()
        fields = stats.fields if hasattr(stats, "fields") else stats
        self.assertIn("tenant", {getattr(f, "field", None) for f in fields})


class AgainstARealClusterTest(unittest.TestCase):
    """The lab, because the limit is the server's and not ours.

    The threshold above is a number in this repository; that it is the right
    side of Elasticsearch's is a claim about Elasticsearch.
    """

    @classmethod
    def setUpClass(cls):
        from tests import lab
        if lab.volume("es-logs") is None:
            raise unittest.SkipTest(
                f"es-logs at {lab.BACKENDS['es-logs'][0]} is not running")
        from elasticsearch import Elasticsearch
        cls.es = Elasticsearch(hosts=[lab.ES], request_timeout=20)
        cls.real = [row["index"] for row in cls.es.cat.indices(format="json")]

    def padded(self, to=563):
        """The lab's own indices, repeated to the width a real cluster has.

        Repeated rather than invented: a name that matches nothing would
        make Elasticsearch answer about the pattern rather than about the
        line length.
        """
        return (self.real * 200)[:to]

    def test_the_url_path_really_is_refused_at_this_size(self):
        """The fault, reproduced. Without this the test below passes on a
        cluster that would have taken the long URL anyway."""
        from elasticsearch import BadRequestError
        with self.assertRaises(BadRequestError) as caught:
            self.es.search(index=",".join(self.padded()),
                           query={"match_all": {}}, size=1)
        self.assertIn("too_long_http_line", str(caught.exception))

    def test_and_the_same_search_answers_through_the_body(self):
        got = _search(self.es, self.padded(), BODY, timeout="15s")
        self.assertIn("hits", got)
        self.assertGreater(got["hits"]["total"]["value"], 0)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
