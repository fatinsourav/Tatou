import pytest

pytestmark = pytest.mark.usefixtures("app_with_db")


def test_create_user_missing_fields(client):
    r = client.post("/api/create-user", json={})
    assert r.status_code == 400
    data = r.get_json()
    assert "error" in data
    assert "required" in data["error"].lower()


def test_create_user_duplicate_email_and_login(client):
    payload = {
        "email": "dup@example.test",
        "login": "dupuser",
        "password": "Password123!",
    }
    # First time should succeed
    r1 = client.post("/api/create-user", json=payload)
    assert r1.status_code in (201, 409)

    # Second time must be a conflict
    r2 = client.post("/api/create-user", json=payload)
    assert r2.status_code == 409
    data = r2.get_json()
    assert "error" in data
    assert "already" in data["error"].lower() or "duplicate" in data["error"].lower()


def test_login_missing_fields(client):
    r = client.post("/api/login", json={})
    assert r.status_code == 400
    data = r.get_json()
    assert "error" in data
    assert "email and password are required" in data["error"]


def test_login_wrong_password(client):
    # create user
    payload = {
        "email": "wrongpw@example.test",
        "login": "wrongpw",
        "password": "Correct123!",
    }
    r = client.post("/api/create-user", json=payload)
    assert r.status_code in (201, 409)

    # wrong password
    r = client.post(
        "/api/login",
        json={"email": payload["email"], "password": "WrongPassword"},
    )
    assert r.status_code == 401
    data = r.get_json()
    assert "error" in data
    assert "invalid credentials" in data["error"].lower()
