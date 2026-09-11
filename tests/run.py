"""
The suite, on every core.

    python -m tests.run            # every module, one process each, all cores
    python -m tests.run -j 4       # four at a time
    python -m tests.run test_store test_identity

`python -m unittest discover -s tests -t .` runs the same tests one after
another in one process, and that is still what CI's matrix runs. This runs
each module in a process of its own, as many at once as there are cores:
the same tests, each module as isolated as when it is run alone — which is
the only way any of them is ever run by hand, and so the way they are
written to pass.

The slowest start first, going by how long each took last time
(tests/.timings*.json, one per dialect, not committed), and a module that took longer than
SPLIT_SECONDS is run a class at a time: one module of real-browser tests
would otherwise be the whole run's wall time. A split module has to run as
many tests as it did whole; if it does not, the run says so and fails.
Output is each failing unit's own unittest output, whole, then one line for
the run.
"""

import argparse
import ast
import json
import os
import re
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
#: Last run's times, one file per dialect: a module that takes seconds on
#: SQLite can take a minute on Postgres, where every store is a new schema
#: migrated from nothing.
TIMINGS = os.path.join(HERE, ".timings-postgres.json" if os.environ.get(
    "WDASH_TEST_POSTGRES") else ".timings.json")

#: Nothing quicker than this, last time, is split, however many cores there
#: are: a process costs most of a second to start, and splitting what is
#: already quick only buys that cost again.
SPLIT_SECONDS = 6.0

_RAN = re.compile(r"^Ran (\d+) tests? in ", re.M)
_VERDICT = re.compile(r"^(OK|FAILED)(?: \((.*)\))?$", re.M)


def modules(wanted=()):
    names = sorted(name[:-3] for name in os.listdir(HERE)
                   if name.startswith("test_") and name.endswith(".py"))
    if wanted:
        names = [n for n in names if any(w in n for w in wanted)]
    return names


def classes(module):
    """The test classes a module defines, read without importing it."""
    with open(os.path.join(HERE, module + ".py")) as handle:
        return classes_in(handle.read())


def classes_in(source):
    """Those with a test method of their own, and those that inherit one.
    Returns {name: [its own test methods, or None when it inherits tests]}."""
    found = {}
    for node in ast.parse(source).body:
        if not isinstance(node, ast.ClassDef):
            continue
        bases = {getattr(b, "id", None) or getattr(b, "attr", None) for b in node.bases}
        own = [item.name for item in node.body
               if isinstance(item, ast.FunctionDef) and item.name.startswith("test")]
        if bases & set(found):
            found[node.name] = None       # its tests are not all its own
        elif own:
            found[node.name] = own
    return found


def units(module, timings, target):
    """What to run as one process: the module, its classes, or — for a slow
    class whose tests are all its own — its tests. Only what would be longer
    than `target`, the wall time the run can hope for, is split."""
    if timings.get(module, 0) <= target:
        return [module]
    out = []
    for name, methods in classes(module).items():
        unit = f"{module}.{name}"
        # Measured on its own, not guessed from its module's: every class of
        # a slow module is not slow, and a guess split them all.
        slow = timings.get(unit, 0) > target
        if slow and methods and len(methods) > 1:
            out += [f"{unit}.{method}" for method in methods]
        else:
            out.append(unit)
    return out or [module]


def _load_timings():
    try:
        with open(TIMINGS) as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return {}


def run_one(unit):
    started = time.monotonic()
    result = subprocess.run(
        [sys.executable, "-m", "unittest", f"tests.{unit}"],
        cwd=ROOT, capture_output=True, text=True)
    output = result.stdout + result.stderr
    ran = sum(int(n) for n in _RAN.findall(output))
    verdict = _VERDICT.findall(output)
    counts = {}
    for _, detail in verdict:
        for part in (detail or "").split(","):
            if "=" in part:
                key, value = part.strip().split("=")
                counts[key] = counts.get(key, 0) + int(value)
    return {"unit": unit, "module": unit.split(".")[0],
            "code": result.returncode, "ran": ran,
            "counts": counts, "seconds": time.monotonic() - started,
            "output": output}


def main(argv=None):
    parser = argparse.ArgumentParser(prog="python -m tests.run")
    parser.add_argument("-j", "--jobs", type=int, default=os.cpu_count() or 2)
    parser.add_argument("names", nargs="*", help="run only modules naming these")
    arguments = parser.parse_args(argv)

    timings = _load_timings()
    chosen = modules(arguments.names)
    # The wall time the run can hope for: all of last time's work shared
    # between the workers. Anything longer is what the run would wait on.
    work = sum(timings.get(m, 0) for m in chosen)
    target = max(SPLIT_SECONDS, work / max(1, arguments.jobs))
    queue = sorted((unit for module in chosen
                    for unit in units(module, timings, target)),
                   key=lambda u: timings.get(u, timings.get(u.split(".")[0], 1000)),
                   reverse=True)
    if not queue:
        print("no test modules matched", file=sys.stderr)
        return 2

    started = time.monotonic()
    results = []
    with ThreadPoolExecutor(max_workers=max(1, arguments.jobs)) as pool:
        futures = [pool.submit(run_one, module) for module in queue]
        for future in as_completed(futures):
            outcome = future.result()
            results.append(outcome)
            if outcome["code"] != 0:
                print(f"\n{'=' * 70}\n{outcome['unit']} FAILED\n{'=' * 70}")
                print(outcome["output"].rstrip())
    wall = time.monotonic() - started

    per_module, per_class, counted = {}, {}, {}
    for r in results:
        per_module[r["module"]] = per_module.get(r["module"], 0) + r["seconds"]
        counted[r["module"]] = counted.get(r["module"], 0) + r["ran"]
        # A class split into its tests keeps a time of its own, or the next
        # run finds it quick and runs it whole again.
        if r["unit"].count(".") == 2:
            owner = r["unit"].rsplit(".", 1)[0]
            per_class[owner] = per_class.get(owner, 0) + r["seconds"]
    # A split that ran fewer tests than the module did whole has lost some:
    # a class the reader above did not recognise. Counts are taken from
    # whole runs only, and kept across split ones.
    whole = {r["module"]: r["ran"] for r in results if r["unit"] == r["module"]}
    known = dict(timings.get("counts", {}))
    lost = [f"{m} ran {n} of {known[m]}" for m, n in sorted(counted.items())
            if m not in whole and m in known and n < known[m]]
    for m in lost:
        print(f"\nSPLIT LOST TESTS: {m}")
    known.update(whole)
    record = {"counts": known}
    record.update({r["unit"]: round(r["seconds"], 2) for r in results})
    record.update({c: round(t, 2) for c, t in per_class.items()})
    record.update({m: round(t, 2) for m, t in per_module.items()})
    try:
        with open(TIMINGS, "w") as handle:
            json.dump(record, handle, indent=0, sort_keys=True)
    except OSError:
        pass

    failed = [r for r in results if r["code"] != 0]
    ran = sum(r["ran"] for r in results)
    totals = {}
    for r in results:
        for key, value in r["counts"].items():
            totals[key] = totals.get(key, 0) + value
    slowest = max(results, key=lambda r: r["seconds"])
    detail = ", ".join(f"{k}={v}" for k, v in sorted(totals.items()))
    print(f"\nRan {ran} tests in {len(per_module)} modules ({len(results)} "
          f"processes), {arguments.jobs} at a time, in {wall:.1f}s (the slowest, "
          f"{slowest['unit']}, took {slowest['seconds']:.1f}s)")
    print(("FAILED" if failed or lost else "OK") + (f" ({detail})" if detail else ""))
    if failed:
        print("failing: " + ", ".join(r["unit"] for r in failed))
    return 1 if failed or lost else 0


if __name__ == "__main__":
    sys.exit(main())
