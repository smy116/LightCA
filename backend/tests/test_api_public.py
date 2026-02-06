import pytest
from fastapi.testclient import TestClient


class TestPublicAPI:
    """Test public API endpoints"""

    def test_health_check(self, client: TestClient):
        response = client.get("/public/health")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"

    def test_public_health_returns_json(self, client: TestClient):
        response = client.get("/public/health")

        assert response.headers["content-type"] == "application/json"

    def test_public_ca_download_not_found(self, client: TestClient):
        response = client.get("/public/ca/99999.crt")

        assert response.status_code == 404

    def test_public_crl_download_not_found(self, client: TestClient):
        response = client.get("/public/crl/99999.crl")

        assert response.status_code == 404

    def test_public_endpoints_no_auth_required(self, client: TestClient):
        health_response = client.get("/public/health")
        assert health_response.status_code == 200

        ca_response = client.get("/public/ca/1.crt")
        assert ca_response.status_code in [200, 404]

        crl_response = client.get("/public/crl/1.crl")
        assert crl_response.status_code in [200, 404]
