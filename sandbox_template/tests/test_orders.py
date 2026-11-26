
def _seed_and_login(client, email="buyer@example.com"):
    client.post("/auth/register", json={"email": email, "password": "secret123"})
    client.post("/auth/login", json={"email": email, "password": "secret123"})
    product = client.post(
        "/api/v1/products",
        json={"name": "Gadget", "sku": "G-1", "price_cents": 900},
    )
    return product.json()["id"]


def test_order_uses_existing_models(client):
    product_id = _seed_and_login(client)

    response = client.post(
        "/api/v1/orders",
        json={"product_id": product_id, "quantity": 2},
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["product_id"] == product_id
    assert body["quantity"] == 2
    assert body["status"] == "pending"

    response = client.get("/api/v1/orders")
    assert response.status_code == 200
    assert len(response.json()) == 1


def test_orders_require_authentication(client):
    assert client.get("/api/v1/orders").status_code == 401
