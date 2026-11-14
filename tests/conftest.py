"""pytest fixtures: hermetic app instance with tmp storage dirs."""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import zippass.state as state          # noqa: E402
import zippass.config as config        # noqa: E402
from zippass import create_app         # noqa: E402


@pytest.fixture(autouse=True)
def clean_state():
    """keep the module-level tables empty around every test."""
    for table in (state.UPLOADS, state.MEMBERS, state.JOBS):
        table.clear()
    yield
    for table in (state.UPLOADS, state.MEMBERS, state.JOBS):
        table.clear()


@pytest.fixture()
def app(tmp_path, monkeypatch):
    """app wired to tmp dirs; wordlist sandbox limited to tmp_path."""
    monkeypatch.setattr(config, "UPLOAD_DIR", str(tmp_path / "uploads"))
    monkeypatch.setattr(config, "WORDLIST_DIR", str(tmp_path / "wordlists"))
    monkeypatch.setattr(config, "ALLOWED_WORDLIST_ROOTS", [str(tmp_path)])
    application = create_app()
    application.config.update(TESTING=True)
    yield application


@pytest.fixture()
def client(app):
    return app.test_client()


def pytest_unconfigure(config):
    """the persistent worker pool outlives the session; mark it non-RUN so
    interpreter finalization doesn't trip over its queues."""
    from zippass import jobs
    jobs.quiesce_pool_for_exit()
