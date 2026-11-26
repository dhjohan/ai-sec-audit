
def _login(client, email="seller@example.com"):
    client.post("/auth/register", json={"email": email, "password": "secret123"})
    response = client.post(
        "/auth/login", json={"email": email, "password": "secret123"}
    )
    assert response.status_code == 200, response.text


def test_create_product_requires_authentication(client):
    response = client.post(
        "/api/v1/products",
        json={"name": "Widget", "sku": "W-1", "price_cents": 500},
    )
    assert response.status_code == 401


def test_product_create_list_and_fetch(client):
    _login(client)
    response = client.post(
        "/api/v1/products",
        json={"name": "Widget", "sku": "W-1", "price_cents": 500},
    )
    assert response.status_code == 201, response.text
    product_id = response.json()["id"]

    response = client.get(f"/api/v1/products/{product_id}")
    assert response.status_code == 200
    assert response.json()["sku"] == "W-1"

    response = client.get("/api/v1/products")
    assert response.status_code == 200
    assert [item["sku"] for item in response.json()] == ["W-1"]


def test_missing_product_returns_404(client):
    assert client.get("/api/v1/products/999").status_code == 404
