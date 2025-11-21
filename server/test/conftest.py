import os
import io
import pathlib
import sqlite3

import pytest
from sqlalchemy import create_engine, text, event

# ---------------------------------------------------------------------------
# Make sure sqlite can handle pathlib.Path / PosixPath objects
# ---------------------------------------------------------------------------
# On Linux, paths are typically pathlib.PosixPath. Register adapters so that
# any Path-like object is stored as TEXT in SQLite.
sqlite3.register_adapter(pathlib.Path, lambda p: str(p))
sqlite3.register_adapter(pathlib.PosixPath, lambda p: str(p))

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
                return None
            if isinstance(s, bytes):
                s = s.decode("ascii")
            s = s.strip()
            return binascii.unhexlify(s)

        def last_insert_id():
            # Approximate MySQL's LAST_INSERT_ID() using MAX(id) from Documents.
            cur = dbapi_connection.cursor()
            try:
                cur.execute("SELECT MAX(id) FROM Documents")
                row = cur.fetchone()
            finally:
                cur.close()
            return row[0] if row and row[0] is not None else 1

        dbapi_connection.create_function("UNHEX", 1, unhex)
        dbapi_connection.create_function("LAST_INSERT_ID", 0, last_insert_id)
    # -----------------------------------------------------------------------

    # Minimal schema compatible with the queries in server.py
    ddl_statements = [
        "DROP TABLE IF EXISTS Versions;",
        "DROP TABLE IF EXISTS Documents;",
        "DROP TABLE IF EXISTS Users;",
        """
        CREATE TABLE IF NOT EXISTS Users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE,
            login TEXT NOT NULL UNIQUE,
            hpassword TEXT NOT NULL,
            creation DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS Documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            path TEXT NOT NULL,
            ownerid INTEGER NOT NULL,
            sha256 BLOB NOT NULL,
            size INTEGER NOT NULL,
            creation DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS Versions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            documentid INTEGER NOT NULL,
            link TEXT NOT NULL,
            intended_for TEXT,
            secret TEXT,
            method TEXT,
            position TEXT,
            path TEXT NOT NULL
        );
        """,
        "CREATE INDEX IF NOT EXISTS idx_users_email ON Users(email);",
        "CREATE INDEX IF NOT EXISTS idx_users_login ON Users(login);",
        "CREATE INDEX IF NOT EXISTS idx_docs_owner ON Documents(ownerid);",
        "CREATE INDEX IF NOT EXISTS idx_versions_doc ON Versions(documentid);",
        "CREATE INDEX IF NOT EXISTS idx_versions_link ON Versions(link);",
    ]

    with engine.begin() as conn:
        for stmt in ddl_statements:
            conn.execute(text(stmt))

    # Tell the Flask app to use this engine instead of MySQL
    app.config["_ENGINE"] = engine
    app.config["TESTING"] = True

    yield app

    # Tear-down
    try:
        engine.dispose()
    finally:
        if sqlite_path.exists():
            sqlite_path.unlink()


@pytest.fixture(scope="session")
def client(app_with_db):
    """Flask test client that talks to the real app but backed by SQLite."""
    return app_with_db.test_client()


@pytest.fixture(scope="session")
def auth_token(client):
    """
    Create a test user via the real /api/create-user route and obtain a JWT
    token via /api/login. The same token is reused for all tests.
    """
    email = "testuser@example.test"
    login = "testuser"
    password = "Password123!"

    # Create user (201 on first run, 409 if user already exists)
    r = client.post(
        "/api/create-user",
        json={"email": email, "login": login, "password": password},
    )
    assert r.status_code in (201, 409), r.get_data(as_text=True)

    # Log in and get token
    r = client.post(
        "/api/login",
        json={"email": email, "password": password},
    )
    assert r.status_code == 200, r.get_data(as_text=True)
    data = r.get_json() or {}
    token = data.get("token") or data.get("access_token")
    assert token, f"login did not return token: {data}"

    return token


@pytest.fixture(scope="session")
def auth_headers(auth_token):
    """Convenience fixture: Authorization header for authenticated routes."""
    if not auth_token.startswith("Bearer "):
        return {"Authorization": f"Bearer {auth_token}"}
    return {"Authorization": auth_token}


@pytest.fixture
def tiny_valid_pdf_bytes():
    """
    Return a tiny but syntactically valid one-page PDF as bytes.
    This is good enough for watermarking tests and upload tests.
    """
    return b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n"


@pytest.fixture
def tiny_valid_pdf_file(tmp_path, tiny_valid_pdf_bytes):
    """Create a small PDF file on disk and return its pathlib.Path."""
    p = tmp_path / "test.pdf"
    p.write_bytes(tiny_valid_pdf_bytes)
    return p


@pytest.fixture
def tiny_valid_pdf_fileobj(tiny_valid_pdf_bytes):
    """Return a BytesIO object with a small PDF in it."""
    buf = io.BytesIO(tiny_valid_pdf_bytes)
    buf.name = "test.pdf"
    return buf
