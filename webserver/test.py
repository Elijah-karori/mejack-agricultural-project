from fastapi.testclient import TestClient

# Assuming your FastAPI app is named 'app'
from main import app

client = TestClient(app)

def test_register_user():
    response = client.post(
        "/register",
        json={
            "username": "testuser",
            "email": "testuser@example.com",
            "full_name": "Test User",
            "password": "testpassword",
        },
    )
    assert response.status_code == 200
    assert response.json() == {
        "username": "testuser",
        "email": "testuser@example.com",
        "full_name": "Test User",
    }

def test_login():
    response = client.post(
        "/token",
        data={"username": "testuser", "password": "testpassword"},
    )
    assert response.status_code == 200
    assert "access_token" in response.json()

    # Use the obtained access token for subsequent requests
    access_token = response.json()["access_token"]

    # Assuming you have a /users/me/ endpoint
    response = client.get("/users/me/", headers={"Authorization": f"Bearer {access_token}"})
    assert response.status_code == 200
    assert response.json()["username"] == "testuser"
    assert response.json()["email"] == "testuser@example.com"

def test_read_own_items():
    response = client.post(
        "/token",
        data={"username": "testuser", "password": "testpassword"},
    )
    assert response.status_code == 200
    assert "access_token" in response.json()

    access_token = response.json()["access_token"]

    response = client.get("/users/me/items/", headers={"Authorization": f"Bearer {access_token}"})
    assert response.status_code == 200
    assert len(response.json()) == 1
    assert response.json()[0]["owner"] == "testuser"
    assert response.json()[0]["item_id"] == "Foo"
