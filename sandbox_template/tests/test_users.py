def test_me_requires_authentication(client):
    assert client.get("/api/v1/users/me").status_code == 401


def test_me_returns_current_user(client):
    client.post(
        "/auth/register",
        json={"email": "user@example.com", "password": "secret123"},
    )
    client.post(
        "/auth/login",
        json={"email": "user@example.com", "password": "secret123"},
    )
    response = client.get("/api/v1/users/me")
    assert response.status_code == 200
    assert response.json()["email"] == "user@example.com"
