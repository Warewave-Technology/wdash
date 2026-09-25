"""
The stack-trace grammars WDash publishes, run against the languages.

`docs/multiline-parsers.conf` is configuration for somebody else's process,
printed in the documentation with a measurement beside each line: "5 -> 2",
"8 -> 2". Nothing in this repository executes it, which makes every one of
those numbers a claim that can go stale without a single test going red —
a regex edited for one language, a fluent-bit release that tightens a rule,
a sample nobody re-read.

So this takes the measurements again. Where fluent-bit is installed it runs
each grammar against a real trace of its language and asserts the trace came
out as ONE record; where it is not, those checks skip and the ones about
drift still run, because the file and the page carrying different grammars
is a fault that needs no fluent-bit to find.

Each sample ends with an ordinary log line. A grammar that swallows what
follows it joins the traces beautifully and eats the next request, and a
check that only counted records would call that a pass.
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = os.path.join(os.path.dirname(__file__), "..")
CONF = os.path.join(ROOT, "docs", "multiline-parsers.conf")
PAGE = os.path.join(ROOT, "site", "docs", "index.html")

#: One real trace per grammar, and an ordinary line after it. The last line
#: is never part of the trace.
SAMPLES = {
    "dotnet": [
        "Unhandled exception. System.NullReferenceException: Object reference "
        "not set to an instance of an object.",
        "   at Warewave.Orders.OrderService.Place(Order order) in "
        "/src/OrderService.cs:line 88",
        "   at Warewave.Orders.OrderController.Post(OrderRequest request) in "
        "/src/OrderController.cs:line 41",
        "--- End of stack trace from previous location ---",
        "   at Microsoft.AspNetCore.Server.Kestrel.Core.Internal.Http."
        "HttpProtocol.ProcessRequests[TContext](IHttpApplication`1 application)",
        "GET /api/orders 200 12ms",
    ],
    "dotnet_aspnet": [
        "fail: Microsoft.AspNetCore.Diagnostics.ExceptionHandlerMiddleware[1]",
        "      An unhandled exception has occurred while executing the request.",
        "      System.InvalidOperationException: Sequence contains no elements",
        "         at System.Linq.ThrowHelper.ThrowNoElementsException()",
        "         at Warewave.Orders.OrderService.Place(Order order) in "
        "/src/OrderService.cs:line 88",
        "GET /api/orders 200 12ms",
    ],
    "node": [
        "/app/src/order.js:88",
        "      throw new Error('customer is null');",
        "      ^",
        "",
        "Error: customer is null",
        "    at place (/app/src/order.js:88:13)",
        "    at post (/app/src/controller.js:41:5)",
        "    at process.processTicksAndRejections "
        "(node:internal/process/task_queues:95:5)",
        "GET /api/orders 200 12ms",
    ],
    "php": [
        "PHP Fatal error:  Uncaught TypeError: place(): Argument #1 ($id) must "
        "be of type int, string given in /app/src/Order.php:88",
        "Stack trace:",
        "#0 /app/src/Controller.php(41): Warewave\\Order->place('abc')",
        "#1 /app/public/index.php(12): Warewave\\Controller->post()",
        "#2 {main}",
        "  thrown in /app/src/Order.php on line 88",
        "GET /api/orders 200 12ms",
    ],
    "rust": [
        "thread 'tokio-runtime-worker' panicked at src/order.rs:88:9:",
        "called `Option::unwrap()` on a `None` value",
        "stack backtrace:",
        "   0: rust_begin_unwind",
        "             at /rustc/07dca48/library/std/src/panicking.rs:645:5",
        "   1: core::panicking::panic_fmt",
        "             at /rustc/07dca48/library/core/src/panicking.rs:72:14",
        "   2: warewave_order::place",
        "             at ./src/order.rs:88:9",
        "GET /api/orders 200 12ms",
    ],
    "elixir": [
        "** (RuntimeError) customer is null",
        "    (warewave 0.1.0) lib/warewave/order.ex:88: Warewave.Order.place/1",
        "    (warewave 0.1.0) lib/warewave/controller.ex:41: "
        "Warewave.Controller.post/2",
        "    (phoenix 1.7.0) lib/phoenix/router.ex:432: Phoenix.Router.__call__/5",
        "GET /api/orders 200 12ms",
    ],
    "java_spring": [
        "2026-09-26 09:14:02.113 ERROR 1 --- [nio-8080-exec-3] "
        "c.w.order.OrderController : Failed to place order",
        'java.lang.NullPointerException: Cannot invoke "Customer.getId()" '
        'because "customer" is null',
        "\tat com.warewave.order.OrderService.place(OrderService.java:88)",
        "\tat com.warewave.order.OrderController.post(OrderController.java:41)",
        "Caused by: java.lang.IllegalStateException: customer cache miss",
        "\tat com.warewave.order.CustomerCache.get(CustomerCache.java:57)",
        "\t... 23 more",
        # NOT a following request line: this grammar starts an event at every
        # timestamped line, so an untimestamped one would be read as part of
        # the trace. That is the trade the file states, and the sample has to
        # be honest about it.
        "2026-09-26 09:14:03.001 INFO 1 --- [nio-8080-exec-4] "
        "c.w.order.OrderController : GET /api/orders 200",
    ],
}


#: A line that matches no `cont` rule in any grammar here, so it closes the
#: record before it. Checked against all seven: none of them continues on a
#: bare word at column 0 — `dotnet` wants `at ` or `--- `, `elixir` and
#: `rust` want leading space, `java_spring` wants an Exception or an Error.
SENTINEL = "wdash-sentinel"


def _read(path):
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def _parsers(text):
    """name -> its rules, as `[MULTILINE_PARSER]` blocks."""
    found = {}
    for block in text.split("[MULTILINE_PARSER]")[1:]:
        # On the page a block ends at its code fence, and the prose after it
        # holds words that a rule pattern would happily match.
        block = block.split("</pre>", 1)[0]
        name = re.search(r"^\s*name\s+(\S+)", block, re.M)
        rules = re.findall(r'^\s*rule\s+(.+?)\s*$', block, re.M)
        if name:
            # Whitespace inside a rule line is alignment, not meaning.
            found[name.group(1)] = [re.sub(r"\s+", " ", r) for r in rules]
    return found


class TheFileAndThePageAgreeTest(unittest.TestCase):
    """Two copies of a regex drift, and nothing about the page would show it."""

    def setUp(self):
        self.file = _parsers(_read(CONF))
        self.page = _parsers(_read(PAGE).replace("&quot;", '"')
                             .replace("&lt;", "<").replace("&gt;", ">")
                             .replace("&amp;", "&"))

    def test_the_file_defines_a_grammar_for_every_sample_here(self):
        """A sample with no grammar measures nothing; a grammar with no
        sample is published without ever having been run."""
        self.assertEqual(sorted(self.file), sorted(SAMPLES))

    def test_every_grammar_in_the_file_is_on_the_page(self):
        missing = sorted(set(self.file) - set(self.page))
        self.assertEqual(missing, [],
                         "grammars shipped but never documented")

    def test_and_the_rules_are_the_same_rules(self):
        """Character for character, once alignment is taken out. A regex
        tightened in one place and not the other is the whole reason this
        file is tested rather than read."""
        for name, rules in self.file.items():
            with self.subTest(parser=name):
                self.assertEqual(self.page.get(name), rules)


@unittest.skipUnless(shutil.which("fluent-bit"),
                     "no fluent-bit — the grammars cannot be run")
class TheGrammarsStillJoinTest(unittest.TestCase):
    """Run, not read. The numbers on the page came from here."""

    @classmethod
    def setUpClass(cls):
        cls.version = subprocess.run(
            ["fluent-bit", "--version"], capture_output=True, text=True
        ).stdout.strip().splitlines()[0]

    def _records(self, parser, lines):
        work = tempfile.mkdtemp()
        log = os.path.join(work, "cri.log")
        with open(log, "w", encoding="utf-8") as handle:
            for number, line in enumerate(list(lines) + [SENTINEL]):
                handle.write(f"2026-09-26T09:14:02.{number:03d}Z stderr F "
                             f"{line}\n")
        conf = os.path.join(work, "fb.conf")
        with open(conf, "w", encoding="utf-8") as handle:
            handle.write(
                f"[SERVICE]\n    flush 1\n    log_level error\n"
                f"    parsers_file {os.path.abspath(CONF)}\n"
                f"[INPUT]\n    Name tail\n    Path {log}\n    Tag t\n"
                f"    Read_from_Head true\n    multiline.parser cri\n"
                f"[FILTER]\n    Name multiline\n    Match *\n"
                f"    multiline.key_content log\n    mode parser\n"
                f"    multiline.parser {parser}\n"
                f"[OUTPUT]\n    Name stdout\n    Match *\n"
                f"    Format json_lines\n")
        out = os.path.join(work, "out.jsonl")
        with open(out, "w") as handle:
            proc = subprocess.Popen(["fluent-bit", "-c", conf], stdout=handle,
                                    stderr=subprocess.DEVNULL)
            # Waited for a thing rather than for a duration. A fixed sleep
            # is a test that has only met this machine — three seconds
            # failed here and five passed, and neither number is about
            # fluent-bit. Waiting for the output to go quiet was no better:
            # the LAST record of a file sits in the grammar's buffer until
            # its own `flush_timeout` expires, so the file is still while a
            # record is still coming.
            #
            # `SENTINEL` is the fix. It matches no `cont` rule in any
            # grammar here, so it closes whatever record was open and pushes
            # it out; seeing it in the output means everything before it has
            # already been written. Only the sentinel is then left buffered,
            # and nothing asks about it.
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                time.sleep(0.2)
                if SENTINEL in _read(out):
                    break
            proc.terminate()
            proc.wait(timeout=10)
        records, swallowed = [], []
        for raw in _read(out).splitlines():
            try:
                log = json.loads(raw)["log"]
            except Exception:
                continue
            if SENTINEL not in log:
                records.append(log)
            elif log.strip() != SENTINEL:
                # The sentinel is supposed to arrive alone, having closed the
                # record before it. Arriving INSIDE one means the grammar
                # continues on anything and swallowed it — reported here,
                # because filtering it out silently leaves an empty list and
                # "fluent-bit produced nothing", which sends the next reader
                # looking at fluent-bit.
                swallowed.append(log)
        shutil.rmtree(work, ignore_errors=True)
        self.assertEqual(
            swallowed, [],
            f"{parser}: this grammar continues on anything — it absorbed "
            f"even the line written to close the record")
        return records

    def test_each_grammar_joins_its_trace_and_nothing_else(self):
        """Two assertions about ONE run of each sample.

        Asking them separately ran fluent-bit twice per language and made
        this the slowest module in the suite. They are also one question:
        a grammar is right when the trace is gathered AND the line after it
        is left alone, and a grammar that eats the next request passes the
        first half beautifully.
        """
        for parser, lines in SAMPLES.items():
            with self.subTest(parser=parser, fluent_bit=self.version):
                records = self._records(parser, lines)
                self.assertTrue(records, "fluent-bit produced nothing at all")

                trace = [line for line in lines[:-1] if line]
                self.assertTrue(
                    [rec for rec in records
                     if all(line in rec for line in trace)],
                    f"{parser}: the trace is spread over {len(records)} "
                    f"records rather than gathered into one")

                self.assertTrue(
                    any(rec.strip() == lines[-1].strip() for rec in records),
                    f"{parser}: the line after the trace was swallowed into "
                    f"it rather than left alone")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
