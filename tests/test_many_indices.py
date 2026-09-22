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
    MAX_INDICES_IN_URL, _search,
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
