"""global error boundary - details to the log, safe JSON to the client."""
import logging

from werkzeug.exceptions import HTTPException

log = logging.getLogger("zippass.errors")


def register(app) -> None:
    @app.errorhandler(HTTPException)
    def http_error(e):
        """flask's default html pages -> json with correct status."""
        return {"error": e.description or e.name}, e.code

    @app.errorhandler(Exception)
    def unhandled(e):
        """programmer/operational errors: full traceback to the log only."""
        app.logger.exception("unhandled error")
        log.exception("unhandled error")
        return {"error": "internal server error"}, 500
