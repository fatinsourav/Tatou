import re

from flask import Flask
from sqlalchemy.engine import Engine

from server import _db_url_from_cfg, get_engine


def test_db_url_from_cfg_builds_mysql_url():
    cfg = {
        "DB_USER": "user",
        "DB_PASSWORD": "pass",
        "DB_HOST": "localhost",
        "DB_PORT": 3306,
        "DB_NAME": "tatou",
    }

    url = _db_url_from_cfg(cfg)

    # Basic structure check
    assert url.startswith("mysql+pymysql://user:pass@localhost:3306/tatou")

    # And the charset suffix is present
    assert url.endswith("?charset=utf8mb4")


def test_get_engine_creates_and_reuses_engine():
    app = Flask(__name__)

    # Set a dummy DB config – it doesn't need to be reachable, we're only
    # checking that SQLAlchemy Engine objects are created & cached.
    app.config.update(
        DB_USER="user",
        DB_PASSWORD="pass",
        DB_HOST="localhost",
        DB_PORT=3306,
        DB_NAME="tatou",
    )

    with app.app_context():
        # First call should create an Engine and store it on app.config["_ENGINE"]
        eng1 = get_engine()
        assert isinstance(eng1, Engine)
        assert app.config.get("_ENGINE") is eng1

        # Second call should return the same Engine instance (no new connection pool)
        eng2 = get_engine()
        assert eng2 is eng1
