"""
Choosing which fields the log sidebar counts.

The sidebar discovers what a source's mapping offers and shows the first ten
BY NAME. That is not a ranking, it is `sorted()`, and on a real cluster it
produced a panel of `@i`, `@l`, `@m`, `@sp`, `@tr` and one application's own
counter — three of them holding a single value seen once — while
`kubernetes.container_name`, which is what a person there would filter by,
never reached the list at all. `@` sorts before letters; that was the whole
of it.

The priority list that exists to prevent this,
`_PRIORITY_FIELDS = ("level", "service", "host", "environment")`, is written
in one shape's spelling and matched nothing in that cluster: the level is
`@l` there, the service `kubernetes.container_name`.

So: somebody says which fields matter, per source, and the sidebar counts
those. Not chosen is the old behaviour exactly, because a default that
changes under an installation that never asked is its own surprise.

Three decisions this file pins, each of them a way the feature could look
like it worked while doing nothing:

  * the offer is the WHOLE mapping, not the ten the sidebar shows — a picker
    that offers what is already on screen cannot fix what is missing from it;
  * a chosen field the mapping no longer has is NAMED, not dropped. An index
    rolls over, a source is re-pointed, and a panel that silently gets
    shorter reads as a quiet hour;
  * saving an empty list REMOVES the entry rather than storing one, so a
    cleared choice and a never-made one are the same state.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from datetime import datetime, timezone  # noqa: E402

from tests.support import ModelledES, grant  # noqa: E402
from tests.test_log_contract import TestConfig, _session  # noqa: E402
from wdash.api.log_routes import STATS_FIELDS_SETTING  # noqa: E402
from wdash.app import create_app  # noqa: E402
from wdash.hub import Hub, Scope  # noqa: E402
from wdash.hub.adapters import ElasticsearchLogSource  # noqa: E402

START = "2026-09-22T13:00:00Z"
END = "2026-09-22T14:00:00Z"

#: A mapping in the reported cluster's shape: the useful names sort after the
#: punctuation ones, which is the fault in one line.
MAPPING = {
    "@timestamp": {"type": "date"},
    "@i": {"type": "keyword"},
    "@l": {"type": "keyword"},
    "@sp": {"type": "keyword"},
    "@tr": {"type": "keyword"},
    "ALPACACOUNT": {"type": "keyword"},
    "Application": {"type": "keyword"},
    "ConnectionId": {"type": "keyword"},
    "EventId": {"type": "keyword"},
    "RequestId": {"type": "keyword"},
    "RequestPath": {"type": "keyword"},
    "SourceContext": {"type": "keyword"},
    "stream": {"type": "keyword"},
    "kubernetes": {"properties": {
        "container_name": {"type": "keyword"},
        "host": {"type": "keyword"},
        "namespace_name": {"type": "keyword"},
    }},
}


#: Enough records for a ranking to be able to tell two fields apart.
#:
#: With three of them every field scores three, whatever its shape, and a
#: panel that shows ten out of nine has nothing to choose. The distribution
#: below is the reported cluster's: a handful of fields that describe the
#: records, and four whose values are unique per record — a span, a trace,
#: a connection and a request — which is what filled the sidebar.
RECORDS = 40


def _document(number):
    return {"_id": f"d{number}", "@timestamp": "2026-09-22T13:30:00Z",
            "@l": "Warning" if number % 4 else "Error",
            "@i": f"9fb525a{number % 3}",
            "@sp": f"span{number}", "@tr": f"trace{number}",
            "ConnectionId": f"conn{number}", "RequestId": f"req{number}",
            "RequestPath": "/api/symbols" if number % 2 else "/api/orders",
            "Application": "superapp", "EventId": f"{number % 3}",
            "SourceContext": "Warewave.Content.Controllers",
            "ALPACACOUNT": "13078397580", "stream": "stdout",
            "kubernetes": {"container_name": "content-service",
                           "host": "10.0.40.110",
                           "namespace_name": "superapp"}}


class _Base(unittest.TestCase):
    def setUp(self):
        self.es = ModelledES({"kube-superapp-2026.09.22":
                              (MAPPING,
                               [_document(n) for n in range(RECORDS)])})
        self.app = create_app(TestConfig)
        hub = Hub()
        hub.add_logs(ElasticsearchLogSource(self.es, name="k8s",
                                            patterns=("kube-*",)))
        self.app.hub = hub
        self.client = self.app.test_client()
        self.login(["logs:read", "system:admin"])

    def login(self, permissions, indices=("*",)):
        grant(self.app, "u", permissions, indices)
        with self.client.session_transaction() as session:
            session["user_data"] = _session(permissions, indices)
            session["_user_id"] = "1"

    def offer(self):
        return self.client.get("/api/field-stats/fields?source=k8s").get_json()

    def choose(self, fields, source="k8s"):
        return self.client.post("/api/field-stats/fields",
                                json={"source": source, "fields": fields})

    def counted(self):
        answer = self.client.get(
            f"/api/field-stats?q=*&source=k8s&start_time={START}"
            f"&end_time={END}").get_json()
        return answer, [field["field"] for field in answer.get("fields", [])]


class WhatTheSidebarShowsWithoutAChoiceTest(_Base):
    """What a source picks when nobody has chosen.

    This used to be the first ten field names, sorted — which is not a
    ranking, and on the cluster that reported it produced `@i`, `@l`, `@m`,
    `@sp`, `@tr` and an application's own counter, three of them holding a
    single value seen once, while `kubernetes.container_name` never
    reached the list at all. `@` sorts before letters; that was the whole
    of it.
    """

    def test_the_source_still_picks(self):
        _, fields = self.counted()
        self.assertTrue(fields)

    def test_the_service_is_shown(self):
        """The priority list is resolved through the neutral names now.
        Spelled `("level", "service", "host", "environment")`, it matched
        nothing here — this cluster calls them `@l` and
        `kubernetes.container_name`."""
        _, fields = self.counted()
        self.assertIn("kubernetes.container_name", fields)

    def test_and_the_level(self):
        _, fields = self.counted()
        self.assertIn("@l", fields)

    def test_and_the_host(self):
        _, fields = self.counted()
        self.assertIn("kubernetes.host", fields)

    def test_a_field_whose_every_value_is_unique_is_not(self):
        """A span id over forty records has forty values, one each, and the
        ten the panel can show account for a quarter of them. It says
        nothing about the hour, and four fields like it — the span, the
        trace, the connection, the request — were taking four of the ten
        slots on the cluster that reported this."""
        _, fields = self.counted()
        for unique in ("@sp", "@tr", "ConnectionId", "RequestId"):
            self.assertNotIn(unique, fields)

    def test_while_a_field_that_describes_the_records_is(self):
        _, fields = self.counted()
        self.assertIn("RequestPath", fields)

    def test_and_ten_is_still_what_it_shows(self):
        _, fields = self.counted()
        self.assertEqual(len(fields), 10)

    def test_and_nothing_says_a_choice_was_made(self):
        answer, _ = self.counted()
        self.assertNotIn("chosen", answer)


class WhenTheSpellingSortsLateTest(_Base):
    """The priority list has to be resolved, not matched.

    Everything above happens to use `@l`, which sorts before letters and
    would survive any cut by accident. These use `severity_text` — the
    OpenTelemetry Collector's spelling — in a mapping full of `attr_*`,
    where a name that is merely eligible is a name that gets cut.
    """

    def source(self, extra=None):
        """Forty records where the level and the service are on every one
        and each `attr_*` is on a single record.

        The distribution matters: with one record every field scores the
        same and nothing the ranking does is visible. Here a promoted
        field wins its slot and an unpromoted one cannot, which is what
        makes promotion observable at all.
        """
        mapping = {"@timestamp": {"type": "date"},
                   "severity_text": {"type": "keyword"},
                   "resource.attributes.service.name": {"type": "keyword"}}
        mapping.update(extra or {})
        mapping.update({f"attr_{n:04d}": {"type": "keyword"}
                        for n in range(60)})
        documents = []
        for number in range(40):
            document = {"_id": f"d{number}",
                        "@timestamp": "2026-09-22T13:30:00Z",
                        "severity_text": "ERROR" if number % 3 else "WARN",
                        "resource.attributes.service.name": "api"}
            document.update({key: "x" for key in (extra or {})})
            document[f"attr_{number:04d}"] = f"v{number}"
            documents.append(document)
        es = ModelledES({"kube-otel": (mapping, documents)})
        source = ElasticsearchLogSource(es, name="otel", patterns=("kube-*",))
        self.app.hub.add_logs(source)
        return source

    def shown(self, extra=None):
        self.source(extra)
        answer = self.client.get(
            f"/api/field-stats?q=*&source=otel&start_time={START}"
            f"&end_time={END}").get_json()
        return [field["field"] for field in answer["fields"]]

    def test_the_collectors_spelling_of_the_level_is_shown(self):
        """`severity_text` sorts after sixty `attr_*`. Spelled into the
        priority list as `level`, it matched nothing and was cut."""
        self.assertIn("severity_text", self.shown())

    def test_and_its_spelling_of_the_service(self):
        self.assertIn("resource.attributes.service.name", self.shown())

    def test_two_spellings_of_one_name_do_not_take_two_slots(self):
        """A merged view over a flat cluster and a collector's has both
        `level` and `severity_text`, and only the first is pinned: four
        neutral names filling ten slots with two spellings each is a panel
        of synonyms.

        The second is still ELIGIBLE — it just has to earn a slot, and
        earning one means being ASKED about: `severity_text` sorts after
        sixty `attr_*`, so without a promotion it is not among the thirty
        the sidebar asks about and cannot be ranked into the ten it shows,
        however much of the answer it would have accounted for.
        """
        shown = self.shown({"level": {"type": "keyword"}})
        self.assertIn("level", shown)
        self.assertNotIn("severity_text", shown)


class WhenAFilterFieldIsQuietTest(_Base):
    """The four names people filter by are kept whatever they score.

    Without that, an hour in which every record shares a service takes the
    service row away — the control disappears exactly when the thing it
    controls is uniform, which is when somebody is trying to confirm it.
    """

    def setUp(self):
        super().setUp()
        mapping = {"@timestamp": {"type": "date"},
                   "service": {"type": "keyword"}}
        mapping.update({f"attr_{n:04d}": {"type": "keyword"}
                        for n in range(20)})
        documents = []
        for number in range(40):
            document = {"_id": f"d{number}",
                        "@timestamp": "2026-09-22T13:30:00Z"}
            document.update({f"attr_{n:04d}": f"v{n}" for n in range(20)})
            # One record in forty carries a service at all.
            if number == 0:
                document["service"] = "api"
            documents.append(document)
        self.app.hub.add_logs(ElasticsearchLogSource(
            ModelledES({"kube-quiet": (mapping, documents)}),
            name="quiet", patterns=("kube-*",)))

    def shown(self):
        answer = self.client.get(
            f"/api/field-stats?q=*&source=quiet&start_time={START}"
            f"&end_time={END}").get_json()
        return [field["field"] for field in answer["fields"]]

    def test_the_service_is_shown_although_it_accounts_for_one_record(self):
        self.assertIn("service", self.shown())

    def test_and_it_leads(self):
        """Pinned means first, not merely present: a control somebody has
        to scroll to is one they will not find."""
        self.assertEqual(self.shown()[0], "service")


class HowTheTenAreChosenTest(unittest.TestCase):
    """The ranking on its own, so its rule can be stated rather than
    inferred from a panel."""

    def stat(self, field, *counts):
        from wdash.hub.models import FieldStat, FieldValue
        return FieldStat(field=field,
                         values=[FieldValue(value=f"v{n}", count=count)
                                 for n, count in enumerate(counts)])

    def rank(self, stats, keep=3, first=()):
        from wdash.hub.adapters.elasticsearch import _most_telling
        return [s.field for s in _most_telling(stats, keep, first=first)]

    def test_the_field_that_accounts_for_most_of_the_answer_leads(self):
        self.assertEqual(
            self.rank([self.stat("id", 1, 1, 1), self.stat("service", 900, 80),
                       self.stat("tenant", 40)]),
            ["service", "tenant", "id"])

    def test_a_field_whose_top_value_was_seen_once_sinks(self):
        """Not a rule of its own — it falls out of the score. A trace id
        with ten buckets of one scores ten, against a service that scores
        the whole window."""
        ordered = self.rank([self.stat("trace_id", *([1] * 10)),
                             self.stat("severity", 500, 20)], keep=2)
        self.assertEqual(ordered[0], "severity")

    def test_what_it_covers_beats_what_its_biggest_value_is(self):
        """The score is the SUM of the counts shown, not the top one. A
        field split three ways over fifteen records accounts for more of
        the answer than one with a single value on ten, and the question
        is how much of the answer a field explains."""
        self.assertEqual(
            self.rank([self.stat("split", 5, 5, 5), self.stat("one", 10)],
                      keep=2),
            ["split", "one"])

    def test_a_tie_goes_to_the_one_with_fewer_values_to_read(self):
        self.assertEqual(
            self.rank([self.stat("many", 20, 20, 20, 20, 20),
                       self.stat("few", 50, 50)], keep=2),
            ["few", "many"])

    def test_and_then_by_name_so_the_same_answer_reads_the_same(self):
        self.assertEqual(self.rank([self.stat("b", 10), self.stat("a", 10)],
                                   keep=2),
                         ["a", "b"])

    def test_what_people_filter_by_is_kept_whatever_it_scores(self):
        """A quiet hour in which every record shares a service must not
        take the service row away — it is the control, not a statistic."""
        ordered = self.rank([self.stat("chatty", 900, 90),
                             self.stat("service", 1)],
                            keep=1, first=("service",))
        self.assertEqual(ordered, ["service"])

    def test_a_field_with_no_values_scores_nothing_rather_than_raising(self):
        from wdash.hub.models import FieldStat
        self.assertEqual(
            self.rank([FieldStat(field="empty", values=[]),
                       self.stat("real", 5)], keep=2),
            ["real", "empty"])


class WhatThePickerOffersTest(_Base):
    """The whole mapping, and not the ten already on screen."""

    def test_it_offers_more_than_the_sidebar_shows(self):
        offered = self.offer()["fields"]
        _, shown = self.counted()
        self.assertGreater(len(offered), len(shown))

    def test_including_the_one_the_sidebar_cut(self):
        """The point of the feature in a single assertion: a picker that
        could not offer `kubernetes.container_name` would leave the reported
        cluster exactly where it was."""
        self.assertIn("kubernetes.container_name", self.offer()["fields"])

    def test_the_names_are_the_paths_the_panel_labels_with(self):
        """Not neutral names. The sidebar's rows say `kubernetes.namespace_
        name`, so a picker offering `namespace` would be asking about a
        different list from the one on screen."""
        self.assertIn("kubernetes.namespace_name", self.offer()["fields"])

    def test_a_reader_is_told_they_may_not_change_it(self):
        """The server answers this, not the page: which fields a cluster's
        sidebar counts is a property of the deployment, and a control that
        appears and then refuses is worse than one that does not appear."""
        self.login(["logs:read"])
        self.assertFalse(self.offer()["editable"])

    def test_and_an_administrator_that_they_may(self):
        self.assertTrue(self.offer()["editable"])


class WhoSeesTheControlTest(_Base):
    """The TEMPLATE decides, and the page asks nothing on load.

    The first version asked this endpoint when the page opened and hid the
    button on the answer — a request per page load whose only job was to
    decide a button, and on an installation with no reachable source that
    request is a 503 in the console of a page that is working.
    `tests/test_rendered_pages` is what found it.
    """

    def page(self):
        return self.client.get("/logs").get_data(as_text=True)

    def test_an_administrator_gets_it(self):
        self.assertIn('id="fieldStatsPick"', self.page())

    def test_a_reader_does_not(self):
        self.login(["logs:read"])
        self.assertNotIn('id="fieldStatsPick"', self.page())

    def test_and_not_merely_hidden(self):
        """`d-none` on a control somebody may not use is a control they can
        un-hide. The refusal is the POST's; this is about not offering."""
        self.login(["logs:read"])
        self.assertNotIn("fieldStatsPick", self.page())

    def test_a_source_that_cannot_count_fields_says_so(self):
        """Loki declares no field statistics. The picker must say that
        rather than offer an empty list, which reads as "this cluster has no
        fields"."""
        from wdash.hub import Capability

        source = self.app.hub.logs("k8s")
        source.supports = lambda capability: (
            capability is not Capability.FIELD_STATS)
        answer = self.offer()
        self.assertTrue(answer["unsupported"])
        self.assertIn("does not provide field statistics", answer["reason"])

    def test_and_so_does_one_that_counts_but_cannot_list(self):
        """A source can answer `field_stats` and not `stats_fields` — the
        base class raises for both and an adapter may implement one. An
        empty picker there would be a list of nothing, drawn as a choice."""
        def refuse(scope, matching=None):
            raise NotImplementedError("no")

        self.app.hub.logs("k8s").stats_fields = refuse
        answer = self.offer()
        self.assertTrue(answer["unsupported"])
        self.assertIn("does not list the fields", answer["reason"])


class WhatChoosingDoesTest(_Base):
    def test_only_the_chosen_fields_are_counted(self):
        self.choose(["kubernetes.container_name", "@l"])
        _, fields = self.counted()
        self.assertEqual(sorted(fields), ["@l", "kubernetes.container_name"])

    def test_and_the_answer_says_which_they_were(self):
        """So the page can tick them without a second request."""
        self.choose(["@l"])
        answer, _ = self.counted()
        self.assertEqual(answer["chosen"], ["@l"])

    def test_the_choice_is_not_the_choosers(self):
        """It is a setting, not a session. Two people looking at the same
        cluster are looking at the same sidebar — which is the whole reason
        this is stored where it is rather than in a cookie."""
        self.choose(["@l"])
        self.client = self.app.test_client()
        self.login(["logs:read"])
        _, fields = self.counted()
        self.assertEqual(fields, ["@l"])

    def test_it_is_kept_per_source(self):
        """One cluster's field names mean nothing in another's."""
        self.app.hub.add_logs(ElasticsearchLogSource(
            self.es, name="other", patterns=("kube-*",)))
        self.choose(["@l"])
        self.choose(["stream"], source="other")
        stored = self.app.store.settings.get(STATS_FIELDS_SETTING)
        self.assertEqual(stored, {"k8s": ["@l"], "other": ["stream"]})

    def test_a_page_with_one_source_names_none_and_still_saves(self):
        """A page showing ONE source renders no source select, so the body
        names none. The first version refused that with "No source named."
        — on the commonest installation there is, found by opening it.

        The server resolves the default source, which is what every read on
        this page already does with the same empty name.
        """
        answer = self.client.post("/api/field-stats/fields",
                                  json={"fields": ["@l"]})
        self.assertEqual(answer.status_code, 200)
        self.assertEqual(self.app.store.settings.get(STATS_FIELDS_SETTING),
                         {"k8s": ["@l"]})

    def test_and_a_name_no_source_answers_to_is_refused(self):
        """Not stored under a name nothing will ever read back."""
        self.assertEqual(self.choose(["@l"], source="nowhere").status_code,
                         400)

    def test_an_empty_choice_removes_the_entry(self):
        """Rather than storing an empty list. Otherwise "cleared" and "never
        chosen" are two states that behave the same and read differently,
        and one of them is a row nobody can account for."""
        self.choose(["@l"])
        self.choose([])
        self.assertEqual(self.app.store.settings.get(STATS_FIELDS_SETTING), {})

    def test_and_the_sidebar_goes_back_to_the_sources_own(self):
        self.choose(["@l"])
        self.choose([])
        _, fields = self.counted()
        self.assertGreater(len(fields), 1)

    def test_a_choice_longer_than_the_panel_shows_is_shown_whole(self):
        """The ranking cuts what a source picked for itself. A set somebody
        chose is not that: cutting it answers a different question from the
        one they asked, and the field they went looking for is the one that
        goes."""
        wanted = ["@l", "@i", "@sp", "@tr", "ALPACACOUNT", "Application",
                  "ConnectionId", "EventId", "RequestId", "RequestPath",
                  "SourceContext", "stream", "kubernetes.container_name",
                  "kubernetes.host", "kubernetes.namespace_name"]
        self.choose(wanted)
        _, fields = self.counted()
        self.assertEqual(len(fields), len(wanted))

    def test_a_name_repeated_is_stored_once(self):
        """A checkbox list cannot produce this; a script can, and each name
        is an aggregation in the same request."""
        self.choose(["@l", "@l", "@i"])
        self.assertEqual(
            self.app.store.settings.get(STATS_FIELDS_SETTING)["k8s"],
            ["@l", "@i"])


class SearchingTheOfferTest(_Base):
    """The picker's own cut is the sidebar's fault one level up.

    Measured on the lab: 439 aggregatable fields, 300 offered by name, and
    `kubernetes.container_name` in neither the panel nor the picker. A
    filter box that only narrowed what had already been sent could not
    reach it, so the search happens on the server and before the cut.
    """

    def wide(self, **params):
        """A source with more fields than the offer holds."""
        mapping = dict(MAPPING)
        mapping.update({f"attr_{n:04d}": {"type": "keyword"}
                        for n in range(400)})
        es = ModelledES({"kube-wide": (mapping, [_document(0)])})
        self.app.hub.add_logs(ElasticsearchLogSource(es, name="wide",
                                                     patterns=("kube-*",)))
        query = "&".join(f"{k}={v}" for k, v in params.items())
        return self.client.get(
            f"/api/field-stats/fields?source=wide&{query}").get_json()

    def test_without_a_search_the_offer_is_cut_and_says_so(self):
        answer = self.wide()
        self.assertEqual(len(answer["fields"]),
                         ElasticsearchLogSource.STATS_FIELD_LIMIT)
        self.assertTrue(answer["partial"])

    def test_the_fields_people_filter_by_survive_the_cut(self):
        """The priority names are resolved and put first, so the cut can no
        longer hide the service or the host behind four hundred `attr_*` —
        which is exactly what it did on the cluster that reported this."""
        offered = self.wide()["fields"]
        self.assertIn("kubernetes.container_name", offered)
        self.assertIn("kubernetes.host", offered)
        self.assertIn("@l", offered)

    def test_but_an_ordinary_field_can_still_be_past_it(self):
        """Three hundred of four hundred and thirteen. Whatever the order,
        a cut cuts something, and this is what the search is for."""
        self.assertNotIn("attr_0399", self.wide()["fields"])

    def test_a_search_reaches_it(self):
        self.assertIn("attr_0399", self.wide(q="attr_0399")["fields"])

    def test_and_answers_only_what_was_asked_for(self):
        found = self.wide(q="attr_039")["fields"]
        self.assertTrue(all("attr_039" in name for name in found), found)

    def test_a_search_that_fits_is_not_called_partial(self):
        """The warning is about the cut. Carrying it over a complete answer
        tells somebody to narrow index patterns they have already reached
        past."""
        self.assertFalse(self.wide(q="container").get("partial"))

    def test_it_ignores_case(self):
        self.assertIn("ALPACACOUNT", self.wide(q="alpaca")["fields"])

    def test_a_search_that_fits_is_not_called_partial_either(self):
        self.assertFalse(self.wide(q="attr_0399").get("partial"))

    def test_a_search_matching_nothing_answers_nothing(self):
        """Rather than everything, which is what an ignored filter looks
        like from the page."""
        self.assertEqual(self.wide(q="zzzz")["fields"], [])

    def test_a_chosen_field_is_not_added_back_to_a_search(self):
        """Without a search, a chosen field the mapping lost is added to
        the offer so it can be unticked. Doing that to a SEARCH answers
        with something the search did not match, and a list that ignores
        the box above it reads as a box that does nothing."""
        self.wide()          # registers the source the save has to resolve
        saved = self.client.post("/api/field-stats/fields",
                                 json={"source": "wide", "fields": ["@l"]})
        self.assertEqual(saved.status_code, 200, saved.get_json())
        self.assertNotIn("@l", self.wide(q="container")["fields"])


class ResolvingAChoiceTest(_Base):
    """Two faults that only a real cluster showed, and both of them made a
    working choice look like a broken one."""

    def test_a_chosen_field_past_the_offers_cut_is_not_called_missing(self):
        """The offer is cut for display. Resolving against it reported
        every field past the cut as one the cluster had lost — four of
        them at once, with the panel saying so above an empty list."""
        mapping = dict(MAPPING)
        mapping.update({f"attr_{n:04d}": {"type": "keyword"}
                        for n in range(400)})
        es = ModelledES({"kube-wide": (mapping,
                                       [dict(_document(0), attr_0399="x")])})
        self.app.hub.add_logs(ElasticsearchLogSource(es, name="wide",
                                                     patterns=("kube-*",)))
        offered = self.client.get(
            "/api/field-stats/fields?source=wide").get_json()["fields"]
        self.assertNotIn("attr_0399", offered)

        self.client.post("/api/field-stats/fields",
                         json={"source": "wide", "fields": ["attr_0399"]})
        answer = self.client.get(
            f"/api/field-stats?q=*&source=wide&start_time={START}"
            f"&end_time={END}").get_json()
        self.assertEqual([f["field"] for f in answer["fields"]],
                         ["attr_0399"])
        self.assertNotIn("warnings", answer)

    def test_a_text_field_is_counted_on_its_keyword_subfield(self):
        """What a field is CALLED is not what an aggregation runs on. A
        `text` field with a `keyword` sub-field is counted on the
        sub-field, and asking Elasticsearch to aggregate on analysed text
        is a refusal, not an empty panel."""
        mapping = dict(MAPPING)
        mapping["@m"] = {"type": "text",
                         "fields": {"keyword": {"type": "keyword"}}}
        es = ModelledES({"kube-text": (mapping,
                                       [dict(_document(0), **{"@m": "hi"})])})
        source = ElasticsearchLogSource(es, name="texty", patterns=("kube-*",))
        resolved = source.resolve_stats_fields(Scope.unrestricted(), ["@m"])
        self.assertEqual(resolved, {"@m": "@m.keyword"})

    def test_and_a_name_nothing_maps_resolves_to_nothing(self):
        source = self.app.hub.logs("k8s")
        self.assertEqual(
            source.resolve_stats_fields(Scope.unrestricted(), ["nowhere"]), {})

    def test_a_scope_that_permits_nothing_resolves_nothing(self):
        source = self.app.hub.logs("k8s")
        self.assertEqual(
            source.resolve_stats_fields(Scope(containers=()), ["@l"]), {})


class WhenTheSettingIsTheWrongShapeTest(_Base):
    """`settings` is a generic JSON store and this key is one row in it.

    Nothing in WDash writes it as anything but a map — but a row in a
    database is a row somebody can edit, restore from an older shape, or
    reach with a migration, and the sidebar answering 500 because of one is
    worse than the sidebar ignoring it.
    """

    def bad(self, value):
        self.app.store.settings.set(STATS_FIELDS_SETTING, value)

    def test_the_sidebar_still_answers(self):
        for value in ("@l", ["@l"], 7):
            with self.subTest(value=value):
                self.bad(value)
                answer, fields = self.counted()
                self.assertNotIn("error", answer)
                self.assertTrue(fields)

    def test_and_saving_over_it_produces_a_map(self):
        """Not an append to whatever was there. A save that carried the
        broken shape forward would be one an administrator cannot undo from
        the page that broke it."""
        self.bad(["@l"])
        self.choose(["@i"])
        self.assertEqual(self.app.store.settings.get(STATS_FIELDS_SETTING),
                         {"k8s": ["@i"]})


class WhenAChosenFieldGoesTest(_Base):
    """A mapping changes. An index rolls over with a template that drops a
    field, a source is re-pointed at another cluster, somebody renames
    something. The sidebar must not just get shorter."""

    def setUp(self):
        super().setUp()
        self.choose(["@l", "gone_away"])

    def test_the_field_that_remains_is_still_counted(self):
        _, fields = self.counted()
        self.assertEqual(fields, ["@l"])

    def test_and_the_one_that_went_is_named(self):
        answer, _ = self.counted()
        self.assertTrue(answer.get("partial"))
        self.assertIn("gone_away", " ".join(answer.get("warnings", [])))

    def test_it_is_still_offered_so_it_can_be_unticked(self):
        """Dropping it from the offer would leave a stored choice nobody can
        see and nobody can clear."""
        self.assertIn("gone_away", self.offer()["fields"])
        self.assertIn("gone_away", self.offer()["chosen"])

    def test_every_chosen_field_gone_is_said_rather_than_drawn_as_empty(self):
        """And NOT quietly answered with the source's own ten, which would
        look like the choice had never been saved."""
        self.choose(["gone_away", "also_gone"])
        answer, fields = self.counted()
        self.assertEqual(fields, [])
        self.assertTrue(answer["partial"])
        self.assertIn("also_gone", " ".join(answer["warnings"]))


class WhoMayChooseTest(_Base):
    def test_a_reader_may_not(self):
        self.login(["logs:read"])
        self.assertEqual(self.choose(["@l"]).status_code, 403)

    def test_and_nothing_is_written_when_they_try(self):
        """A refusal that still wrote would be the worse bug: the check
        would look like it worked, on a page nobody revisits."""
        self.login(["logs:read"])
        self.choose(["@l"])
        self.assertIsNone(self.app.store.settings.get(STATS_FIELDS_SETTING))

    def test_a_body_naming_a_source_that_is_not_there_is_refused(self):
        self.assertEqual(self.choose(["@l"], source="nowhere").status_code,
                         400)

    def test_a_body_that_is_not_a_list_of_names_is_refused(self):
        for fields in ("@l", [1, 2], {"a": 1}, None):
            with self.subTest(fields=fields):
                answer = self.client.post("/api/field-stats/fields",
                                          json={"source": "k8s",
                                                "fields": fields})
                self.assertEqual(answer.status_code, 400)

    def test_and_so_is_one_asking_for_more_than_the_sidebar_can_run(self):
        """Each name is a terms aggregation in the same request. A body with
        ten thousand in it is a request to run ten thousand of them on every
        search, which is a denial of service with a checkbox for a face."""
        answer = self.choose([f"f{n}" for n in range(500)])
        self.assertEqual(answer.status_code, 400)
        self.assertIn("40", answer.get_json()["error"])


class WhatTheSourceOffersTest(_Base):
    """`stats_fields` itself, under the route."""

    def test_it_lists_every_aggregatable_field(self):
        offered = self.app.hub.logs("k8s").stats_fields(Scope.unrestricted())
        self.assertIn("kubernetes.container_name", offered)
        self.assertIn("ALPACACOUNT", offered)

    def test_a_cluster_with_more_fields_than_the_limit_says_it_was_cut(self):
        """The lab's eleven indices discover 1,465 of them. A list cut in
        silence is a picker that cannot reach the field somebody wants and
        gives them no reason to look further."""
        wide = dict(MAPPING)
        wide.update({f"attr_{n:04d}": {"type": "keyword"} for n in range(400)})
        es = ModelledES({"kube-wide": (wide, [_document(0)])})
        source = ElasticsearchLogSource(es, name="wide", patterns=("kube-*",))
        offered = source.stats_fields(Scope.unrestricted())
        self.assertEqual(len(offered), source.STATS_FIELD_LIMIT)
        self.assertTrue(offered.partial)
        self.assertIn("Narrow", " ".join(offered.warnings))

    def test_a_scope_that_permits_nothing_offers_nothing(self):
        empty = Scope(containers=())
        self.assertEqual(
            list(self.app.hub.logs("k8s").stats_fields(empty)), [])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
