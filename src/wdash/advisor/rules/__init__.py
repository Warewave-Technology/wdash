"""Rule modules.

Importing this package registers every rule. When adding a new category or a
new backend, remember to import it here as well.

Elasticsearch rules are grouped by category because there are thirty-one of
them. The other backends get one module each because they have a handful, and
splitting six rules across five files would be filing rather than structure.
"""

from . import cluster, indices, mappings, queries, security, shards  # noqa: F401
from . import jaeger, loki, tempo, victorialogs  # noqa: F401

__all__ = ["cluster", "indices", "mappings", "queries", "security", "shards",
           "jaeger", "loki", "tempo", "victorialogs"]
