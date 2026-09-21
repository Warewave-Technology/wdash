"""
WDash — a minimal Kibana alternative with RBAC and OIDC support.
"""

#: The one place the version is written down.
#:
#: It was in four: here, `setup.py`, `package.json` and twice in the
#: Kubernetes manifests — and they disagreed. This said 1.0.0 while the
#: published images had reached 2.2.4, and the manifests deployed
#: `wdash-elastic-dashboard:1.0.0`, an image five minor versions behind
#: whatever anybody thought they were running.
#:
#: `tests/test_version.py` fails if any of them drifts again, and `/health`
#: reports it so a running instance can be asked rather than guessed at.
__version__ = "3.0.0"
__author__ = "Warewave"
