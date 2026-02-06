import pytest
from fastapi.testclient import TestClient


class TestAuthAPI:
    """Test authentication API endpoint"""

    def test_login_success(self, client: TestClient):
        response = client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "admin_password"},
        )

        assert response.status_code == 200
        data = response.json()
        assert "token" in data
        assert "expires_at" in data
        assert isinstance(data["token"], str)
        assert len(data["token"]) > 0

    def test_login_wrong_username(self, client: TestClient):
        response = client.post(
            "/api/auth/login",
            json={"username": "wrong_admin", "password": "admin_password"},
        )

        assert response.status_code == 401
        data = response.json()
        assert data["success"] is False
        assert "Invalid username or password" in data["message"]

    def test_login_wrong_password(self, client: TestClient):
        response = client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "wrong_password"},
        )

        assert response.status_code == 401
        data = response.json()
        assert data["success"] is False
        assert "Invalid username or password" in data["message"]

    def test_login_missing_username(self, client: TestClient):
        response = client.post(
            "/api/auth/login",
            json={"password": "admin_password"},
        )

        assert response.status_code == 422
        data = response.json()
        assert data["success"] is False

    def test_login_missing_password(self, client: TestClient):
        response = client.post(
            "/api/auth/login",
            json={"username": "admin"},
        )

        assert response.status_code == 422
        data = response.json()
        assert data["success"] is False
