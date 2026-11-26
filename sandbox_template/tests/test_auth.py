def test_register_login_me_logout(client):
    response = client.post(
        "/auth/register",
        json={"email": "alice@example.com", "password": "secret123"},
    )
    assert response.status_code == 201, response.text
    assert response.json()["email"] == "alice@example.com"

    response = client.post(
        "/auth/login",
        json={"email": "alice@example.com", "password": "secret123"},
    )
    assert response.status_code == 200, response.text
    assert "session" in response.cookies

    response = client.get("/auth/me")
    assert response.status_code == 200
    assert response.json()["email"] == "alice@example.com"

    response = client.post("/auth/logout")
    assert response.status_code == 204

    assert client.get("/auth/me").status_code == 401


def test_duplicate_registration_rejected(client):
    payload = {"email": "bob@example.com", "password": "secret123"}
    assert client.post("/auth/register", json=payload).status_code == 201
    assert client.post("/auth/register", json=payload).status_code == 409


def test_login_with_wrong_password_rejected(client):
    client.post(
        "/auth/register",
        json={"email": "carol@example.com", "password": "secret123"},
    )
    response = client.post(
        "/auth/login",
        json={"email": "carol@example.com", "password": "wrong-password"},
    )
    assert response.status_code == 401
