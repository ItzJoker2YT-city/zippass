"""zippass - local zip password recovery web app.

the package core (candidates, cryptoparse, testers, ghshard) is usable
without flask - the cloud runner imports it headless. the web factory
imports flask lazily so a pip-less runner (or any cli use) never needs it.
"""
import os

from . import config


def create_app():
    """app factory: wire blueprint + error boundary, ensure storage dirs.

    reads config dynamically (module attributes), so tests and deployment
    overrides see patched values.
    """
    from flask import Flask

    os.makedirs(config.UPLOAD_DIR, exist_ok=True)
    os.makedirs(config.WORDLIST_DIR, exist_ok=True)
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = config.MAX_UPLOAD
    from .routes import bp, ui
    app.register_blueprint(bp)
    app.register_blueprint(ui)
    from .errors import register
    register(app)
    return app
