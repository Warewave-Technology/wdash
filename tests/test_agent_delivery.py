"""
How an agent hands its results to the server.

A batch was counted in results only, and anything but a 401 or a 5xx meant
"the server will never want these": the batch was dropped. The proxy in
front of the server took 1m, a journey's failure screenshot rides along with
its result, and a handful of failed journeys passed it. Measured by the scan
through a proxy with nginx's default limit: 5 screenshots and 40 http results
came to 1082 KB, the answer was 413, and 45 pending results became 0 — the
down results never arrived, the monitor stayed green, and nothing on the
server said so.
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from wdash.agent import runner  # noqa: E402
from wdash.agent.runner import Agent  # noqa: E402

LIMIT = 1024 * 1024       # nginx's default, as the proxy used to be


class Answer:
    def __init__(self, status, accepted=None):
        self.status_code = status
        self._accepted = accepted

    def json(self):
        return {"accepted": self._accepted}


class Proxy:
    """Refuses a body over `limit`, as nginx does, and records what got in."""

    def __init__(self, limit=LIMIT, status=None):
        self.limit, self.status = limit, status
        self.bodies, self.delivered = [], []

    def post(self, url, json=None, **kwargs):
        import json as encoding
        size = len(encoding.dumps(json))
        self.bodies.append(size)
        if size > self.limit:
            return Answer(413)
        if self.status:
            return Answer(self.status)
        self.delivered += json["results"]
        return Answer(200, accepted=len(json["results"]))


def _result(n, screenshot_kb=0):
    out = {"monitor_id": f"m{n}", "status": "down", "started_at": "2026-09-11T00:00:00Z"}
    if screenshot_kb:
        out["screenshot"] = {"base64": "A" * screenshot_kb * 1024,
                             "content_type": "image/jpeg"}
    return out


class DeliveryTest(unittest.TestCase):
    def agent(self, proxy, results):
        folder = tempfile.mkdtemp()
        agent = Agent("http://wdash", "t", spool_path=os.path.join(folder, "s.jsonl"),
                      session=proxy)
        agent.spool.add(results)
        return agent

    def drain(self, agent, rounds=50):
        for _ in range(rounds):
            if not agent.spool.pending():
                break
            agent.flush()

    def test_a_batch_too_large_for_the_proxy_is_split_not_dropped(self):
        """The scan's case: five screenshots among forty http results."""
        results = [_result(n) for n in range(40)]
        results[5:10] = [_result(n, screenshot_kb=210) for n in range(5, 10)]
        proxy = Proxy(limit=LIMIT)
        agent = self.agent(proxy, results)
        self.drain(agent)
        self.assertEqual([r["monitor_id"] for r in proxy.delivered],
                         [r["monitor_id"] for r in results],
                         "results were lost, or arrived out of order")
        self.assertEqual(agent.spool.pending(), 0)

    def test_a_delivery_is_kept_under_its_byte_budget(self):
        """Screenshots never make one POST larger than MAX_BATCH_BYTES —
        well under what the server and its proxy accept — when every result
        on its own fits."""
        results = [_result(n, screenshot_kb=500) for n in range(30)]
        proxy = Proxy(limit=16 * 1024 * 1024)
        agent = self.agent(proxy, results)
        self.drain(agent)
        self.assertLessEqual(max(proxy.bodies), runner.MAX_BATCH_BYTES)
        self.assertEqual(len(proxy.delivered), 30)

    def test_one_result_too_large_to_take_is_the_only_one_lost(self):
        results = [_result(0), _result(1, screenshot_kb=2000), _result(2)]
        proxy = Proxy(limit=LIMIT)
        agent = self.agent(proxy, results)
        self.drain(agent)
        self.assertEqual([r["monitor_id"] for r in proxy.delivered], ["m0", "m2"])

    def test_a_result_larger_than_the_budget_still_goes_on_its_own(self):
        """The budget bounds a batch, not a result: one bigger than it is
        sent by itself rather than never."""
        big = runner.MAX_BATCH_BYTES // 1024 + 64
        results = [_result(0), _result(1, screenshot_kb=big), _result(2)]
        proxy = Proxy(limit=16 * 1024 * 1024)
        agent = self.agent(proxy, results)
        self.drain(agent)
        self.assertEqual([r["monitor_id"] for r in proxy.delivered],
                         ["m0", "m1", "m2"])

    def test_not_now_keeps_them(self):
        """408 and 429 say "later", like a 5xx, not "never"."""
        for status in (408, 429, 503):
            with self.subTest(status=status):
                proxy = Proxy(status=status)
                agent = self.agent(proxy, [_result(n) for n in range(3)])
                agent.flush()
                self.assertEqual(agent.spool.pending(), 3)

    def test_a_refusal_the_server_means_is_still_dropped(self):
        """A 400 for a batch will be a 400 for ever; keeping it would block
        everything behind it."""
        proxy = Proxy(status=400)
        agent = self.agent(proxy, [_result(n) for n in range(3)])
        agent.flush()
        self.assertEqual(agent.spool.pending(), 0)


class TheServerLimitTest(unittest.TestCase):
    """The server end: a body over MAX_CONTENT_LENGTH is refused before it is
    read, and the limit is the one the agent's budget sits under."""

    def test_a_body_over_the_limit_is_a_413(self):
        from wdash.app import create_app
        from wdash.config import Config
        from wdash.store import SecretBox

        class TestConfig(Config):
            TESTING = True
            SECRET_KEY = "delivery"
            ENCRYPTION_KEY = SecretBox.generate_key()

        app = create_app(TestConfig)
        _, token = app.store.agents.create("probe")
        body = json.dumps({"results": [_result(0, screenshot_kb=17 * 1024)]})
        response = app.test_client().post(
            "/api/agent/results", data=body, content_type="application/json",
            headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(response.status_code, 413)
        self.assertEqual(app.config["MAX_CONTENT_LENGTH"], 16 * 1024 * 1024)
        self.assertLess(runner.MAX_BATCH_BYTES, app.config["MAX_CONTENT_LENGTH"])


if __name__ == "__main__":
    unittest.main()
