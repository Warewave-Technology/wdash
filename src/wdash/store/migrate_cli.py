"""
Move existing dashboards and saved searches into the metadata database.

Two sources: the JSON files, and the Elasticsearch dashboard store that used
to exist. The second is here because removing a storage backend must not
strand the data somebody put in it — a removal that leaves data unreachable is
a deletion with extra steps.

    PYTHONPATH=src python -m wdash.store.migrate_cli \
        --from-elasticsearch http://localhost:9200

Run before switching DASHBOARD_STORAGE to 'database'. The default is not
flipped automatically: doing so would leave every stored dashboard behind and
present an empty list as though nothing had ever been saved — the failure this
codebase keeps trying to avoid, where "no data" and "we did not look" are
indistinguishable.

    PYTHONPATH=src python -m wdash.store.migrate_cli --dry-run
    PYTHONPATH=src python -m wdash.store.migrate_cli

Idempotent: an object already present by id is skipped, so an interrupted run
can simply be repeated.
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone

from sqlalchemy import select

from . import Store
from .schema import dashboards as dashboards_table
from .schema import saved_searches as searches_table


def _parse_time(value):
    """Keep the original creation time; a bulk import must not restamp history."""
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _load_json(path):
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def _load_elasticsearch(url, index, username=None, password=None,
                        verify_certs=False):
    """Dashboards out of the removed Elasticsearch store.

    Reading the index directly rather than through the class that used to own
    it, because that class is gone. This exists so removing a storage backend
    does not strand the data somebody put in it — a removal that leaves data
    unreachable is a deletion with extra steps.

    Returns records in the same shape as the JSON file, so one importer
    handles both.
    """
    from elasticsearch import Elasticsearch

    arguments = {"hosts": [url], "verify_certs": verify_certs,
                 "ssl_show_warn": verify_certs}
    if username and password:
        arguments["basic_auth"] = (username, password)
    client = Elasticsearch(**arguments)

    try:
        if not client.indices.exists(index=index):
            print(f"No index called {index}; nothing to read.")
            return []
        response = client.search(
            index=index, query={"match_all": {}}, size=10000,
            track_total_hits=True)
    except Exception as exc:
        raise SystemExit(f"Could not read {index}: {exc}")

    hits = response["hits"]["hits"]
    total = response["hits"]["total"]
    total = total.get("value") if isinstance(total, dict) else total
    if total and total > len(hits):
        # Said, not swallowed. A partial import that reports success is how
        # somebody discovers the gap months later.
        raise SystemExit(
            f"{index} holds {total} dashboards and this reads {len(hits)}. "
            f"Raise index.max_result_window and run again rather than "
            f"importing part of it.")

    # The document id IS the dashboard id in that store, and identity has to
    # survive: a dashboard that changes id breaks every link somebody pasted.
    return [dict(hit["_source"], id=hit["_id"]) for hit in hits]


def migrate_dashboards(store, path, dry_run=False, records=None):
    moved, skipped = 0, 0
    with store.engine.connect() as connection:
        existing = {row[0] for row in connection.execute(
            select(dashboards_table.c.id))}

    for record in (records if records is not None else _load_json(path)):
        if record.get("id") in existing:
            skipped += 1
            continue
        if dry_run:
            moved += 1
            continue
        store.dashboards.create_dashboard(
            dashboard_id=record.get("id"),
            created_at=_parse_time(record.get("created_at")),
            name=record.get("name", "Untitled"),
            description=record.get("description", ""),
            query=record.get("query", "*"),
            created_by=record.get("created_by", "unknown"),
            index_patterns=record.get("index_patterns", ["*"]),
            panels=record.get("panels"),
            thresholds=record.get("thresholds"),
            # Carried explicitly. Left out, it normalised to the default —
            # `shared` — so every PRIVATE dashboard came out of the migration
            # visible to everybody. An access widening, applied silently, at
            # the one moment somebody is trusting this to move their data
            # faithfully. A migration that changes what a thing means is not
            # a migration.
            visibility=record.get("visibility"),
            # Same reason: a dashboard that named its source must come out of
            # the move reading from the same store, not from the default one.
            source=record.get("source"))
        moved += 1
    return moved, skipped


def migrate_saved_searches(store, path, dry_run=False):
    moved, skipped = 0, 0
    with store.engine.connect() as connection:
        existing = {row[0] for row in connection.execute(
            select(searches_table.c.id))}

    for record in _load_json(path):
        if record.get("id") in existing:
            skipped += 1
            continue
        if dry_run:
            moved += 1
            continue
        store.saved_searches.create(
            search_id=record.get("id"),
            created_at=_parse_time(record.get("created_at")),
            name=record.get("name", "Untitled"),
            query=record.get("query", "*"),
            time_range=record.get("time_range", "1h"),
            created_by=record.get("created_by", "unknown"))
        moved += 1
    return moved, skipped


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database-url", default=os.environ.get("DATABASE_URL"))
    parser.add_argument("--dashboards", default="data/dashboards.json")
    parser.add_argument("--saved-searches", default="data/saved_searches.json")
    parser.add_argument("--dry-run", action="store_true",
                        help="report what would move, change nothing")
    parser.add_argument("--from-elasticsearch", metavar="URL",
                        help="read dashboards out of the removed "
                             "Elasticsearch store instead of the JSON file")
    parser.add_argument("--index", default="wdash-dashboards",
                        help="index holding them (with --from-elasticsearch)")
    parser.add_argument("--es-username")
    parser.add_argument("--es-password")
    parser.add_argument("--es-verify-certs", action="store_true")
    arguments = parser.parse_args(argv)

    # Pass the RBAC file so an import run before the first app start does not
    # seed built-in defaults and thereby shadow the roles somebody wrote.
    store = Store.open(arguments.database_url,
                       rbac_file=os.environ.get("RBAC_CONFIG_FILE",
                                                "config/rbac.yaml"))
    print(f"Metadata store: {store.describe()}")

    records = None
    if arguments.from_elasticsearch:
        records = _load_elasticsearch(
            arguments.from_elasticsearch, arguments.index,
            arguments.es_username, arguments.es_password,
            arguments.es_verify_certs)
        print(f"Source:         {arguments.index} on "
              f"{arguments.from_elasticsearch}")

    moved, skipped = migrate_dashboards(store, arguments.dashboards,
                                        arguments.dry_run, records=records)
    print(f"Dashboards:     {moved} to move, {skipped} already present"
          if arguments.dry_run else
          f"Dashboards:     {moved} moved, {skipped} already present")

    if arguments.from_elasticsearch:
        # That store never held saved searches, so there is nothing to read
        # and saying so beats reporting "0 moved" as though it had looked.
        print("Saved searches: not stored in Elasticsearch; skipped")
        moved, skipped = 0, 0
    else:
        moved, skipped = migrate_saved_searches(store, arguments.saved_searches,
                                                arguments.dry_run)
    if not arguments.from_elasticsearch:
        print(f"Saved searches: {moved} to move, {skipped} already present"
              if arguments.dry_run else
              f"Saved searches: {moved} moved, {skipped} already present")

    if arguments.dry_run:
        print("\nNothing was written. Re-run without --dry-run to migrate.")
    else:
        print("\nDone. Set DASHBOARD_STORAGE=database to use it — the same"
              " setting covers dashboards and saved searches.")
        print("The JSON files are left untouched, so this is reversible.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
