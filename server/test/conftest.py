import os
import io
import pathlib
import sqlite3

import pytest
from sqlalchemy import create_engine, text, event

# ---------------------------------------------------------------------------
# Basic test configuration
# ---------------------------------------------------------------------------

# Disable rate limiting in tests
os.environ.setdefault("RATELIMIT_ENABLED", "0")
os.environ.setdefault("RATELIMIT_STORAGE_URI", "memory://")

# Dummy DB settings (real connection replaced by our SQLite engine)
os.environ.setdefault("DB_HOST", "localhost")
os.environ.setdefault("DB_PORT", "3306")
os.environ.setdefault("DB_USER", "test")
os.environ.setdefault("DB_PASSWORD", "test")
os.environ.setdefault("DB_NAME", "tatou_test")

# Allow sqlite3 to accept pathlib.Path parameters
sqlite3.register_adapter(pathlib.Path, lambda p: str(p))


@pytest.fixture(scope="session")
def app_with_db():
    """
    Create a SQLite database in a local file, create the minimal schema that the
    server expects (Users/Documents/Versions), and inject the engine into the
    Flask app via app.config["_ENGINE"].

    This makes the server use SQLite for tests instead of MariaDB.
    """
    from server import app  # 'server' is the package from src/server.py

    sqlite_path = pathlib.Path("test_db.sqlite").absolute()
    engine = create_engine(f"sqlite:///{sqlite_path}", future=True)

    # --- Emulate MySQL functions UNHEX() and LAST_INSERT_ID() in SQLite -----
    @event.listens_for(engine, "connect")
    def register_mysql_compat(dbapi_connection, connection_record):
        import binascii

        def unhex(s):
            if s is None:
