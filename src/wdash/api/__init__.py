"""HTTP layer — Flask blueprints.

Routes work through the hub; nothing Elasticsearch-specific appears in this
package.
"""

from .advisor_routes import advisor_bp
from .dashboard_routes import dashboard_bp
from .log_routes import log_bp
from .trace_routes import trace_bp

__all__ = ["advisor_bp", "dashboard_bp", "log_bp", "trace_bp"]
