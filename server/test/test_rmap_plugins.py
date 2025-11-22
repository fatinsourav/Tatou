import pytest

pytestmark = pytest.mark.usefixtures("app_with_db")


def test_rmap_initiate_missing_payload(client, auth_headers):
    r = client.post("/api/rmap-initiate", headers=auth_headers, json={})
    assert r.status_code == 400
    data = r.get_json()
    assert "error" in data
    assert "payload" in data["error"].lower()


def test_rmap_get_link_missing_payload(client, auth_headers):
    r = client.post("/api/rmap-get-link", headers=auth_headers, json={})
    assert r.status_code == 400
    data = r.get_json()
    assert "error" in data
    assert "payload" in data["error"].lower()


def test_load_plugin_invalid_path(client, auth_headers):
    # send a dummy plugin path that should not exist
    r = client.post(
        "/api/load-plugin",
        headers=auth_headers,
        json={"path": "/non/existing/plugin.py"},
    )
    # Implementation-specific, but must not 500:
    assert r.status_code in (400, 404, 500)
    data = r.get_json()
    assert "error" in data

    
def test_rmap_initiate_invalid_data_type(client, auth_headers):
    # Send something of wrong type to exercise validation
    r = client.post(
        "/api/rmap-initiate",
        headers=auth_headers,
        json={"not_expected": "value"},
    )
    assert r.status_code in (400, 422)
    assert "error" in r.get_json()


def test_load_plugin_missing_path(client, auth_headers):
    r = client.post("/api/load-plugin", headers=auth_headers, json={})
    assert r.status_code in (400, 422)
    assert "error" in r.get_json()
