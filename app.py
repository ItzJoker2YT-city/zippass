"""zippass entry point - wiring only. Run: python app.py"""
import logging
import os

from zippass import create_app
from zippass.config import APP_ROOT, HOST, PORT


def _setup_logging() -> None:
    fmt = "%(asctime)s %(levelname)s %(name)s: %(message)s"
    logging.basicConfig(
        level=logging.INFO,
        format=fmt,
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(os.path.join(APP_ROOT, "zippass.log"), encoding="utf-8"),
        ],
    )


if __name__ == "__main__":
    _setup_logging()
    app = create_app()
    from zippass import jobs
    jobs.prewarm_pool()      # pay the worker spawn + jit import once, at boot
    logging.getLogger("zippass").info("serving on http://%s:%d", HOST, PORT)
    app.run(host=HOST, port=PORT, threaded=True)
