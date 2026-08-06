#!/usr/bin/env python3
"""
WDash - Main Entry Point
A minimal Kibana alternative with RBAC and OIDC support
"""

import os
import sys

# Add src to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from wdash.app import create_app

app = create_app()

if __name__ == '__main__':
    # Development server.
    #
    # 127.0.0.1, not 0.0.0.0. `debug=True` turns on the Werkzeug debugger,
    # whose traceback page offers an interactive Python console — so binding
    # every interface publishes a shell to the network the machine is on. The
    # PIN slows that down; it is not a boundary.
    #
    # Override deliberately when it is needed (a container, a VM, a phone on
    # the same wifi):  WDASH_DEV_HOST=0.0.0.0 python main.py
    #
    # Production is gunicorn — see the Dockerfile — and never comes through
    # here.
    app.run(debug=True,
            host=os.environ.get('WDASH_DEV_HOST', '127.0.0.1'),
            port=int(os.environ.get('WDASH_DEV_PORT', 5001)))