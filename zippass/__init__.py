"""zippass - local zip password recovery web app."""
import os

from flask import Flask

from . import config


def create_app() -> Flask:
    """app factory: wire blueprint + error boundary, ensure storage dirs.

    reads config dynamically (module attributes), so tests and deployment
    overrides see patched values.
    """
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
