"""
Elasticsearch connection factory.

This class used to hold all the query logic. Log search, record fetching,
context, field statistics and dashboard aggregations now live in
`wdash.hub.adapters.elasticsearch` and work through the neutral model.

What remains is the connection itself, shared by the hub adapters, the Advisor
and the health check.
"""

from elasticsearch import Elasticsearch


class ElasticsearchClient:
    def __init__(self, config):
        self.config = config

        # Verification was hardcoded off with a note saying it ought to be
        # configurable. Sources added through the config page have had the
        # switch all along, so the one cluster every deployment talks to was
        # the only one that could not verify anything.
        verify = config.get("ELASTICSEARCH_VERIFY_CERTS", False)
        es_config = {
            'hosts': [config["ELASTICSEARCH_URL"]],
            # The client's own timeout. ELASTICSEARCH_TIMEOUT was documented,
            # shipped in the configmap and read into the config, and never
            # passed here: the client kept its default of ten seconds while
            # the searches asked the cluster for thirty, so a slow search was
            # cut off at ten with a timeout the setting said it would not get.
            'request_timeout': config.get("ELASTICSEARCH_TIMEOUT", 30),
            'verify_certs': verify,
            # Only silence the warning when the operator asked for no
            # verification. Otherwise a real certificate problem goes unheard.
            'ssl_show_warn': verify,
        }
        if verify and config.get("ELASTICSEARCH_CA_CERTS"):
            es_config['ca_certs'] = config["ELASTICSEARCH_CA_CERTS"]

        if config["ELASTICSEARCH_USERNAME"] and config["ELASTICSEARCH_PASSWORD"]:
            es_config['basic_auth'] = (
                config["ELASTICSEARCH_USERNAME"],
                config["ELASTICSEARCH_PASSWORD"],
            )

        self.es = Elasticsearch(**es_config)

    def ping(self):
        try:
            return bool(self.es.ping())
        except Exception:
            return False
