import pytest
from fastapi.testclient import TestClient


class TestStatsAPI:
    """Test statistics API endpoint"""

    def test_get_stats(self, client: TestClient, auth_headers: dict):
        response = client.get("/api/stats", headers=auth_headers)

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert "data" in data
        assert "certificates" in data["data"]
        assert "keys" in data["data"]
        assert "templates" in data["data"]
        assert "crls" in data["data"]
        assert "ca_total" in data["data"]["certificates"]

    def test_get_stats_with_data(self, client: TestClient, auth_headers: dict):
        key_response = client.post(
            "/api/keys/create",
            json={"algorithm": "RSA", "key_size": 2048},
            headers=auth_headers,
        )
        key_id = key_response.json()["data"]["key_id"]

        cert_response = client.post(
            "/api/certificates/sign",
            json={
                "key_id": key_id,
                "type": "leaf",
                "subject_dn": "CN=Test Cert,O=Test Org,C=US",
                "validity_days": 90,
                "is_ca": False,
            },
            headers=auth_headers,
        )

        stats_response = client.get("/api/stats", headers=auth_headers)

        assert stats_response.status_code == 200
        data = stats_response.json()
        assert data["success"] is True
        assert data["data"]["keys"]["total"] >= 1
        assert data["data"]["certificates"]["total"] >= 1

    def test_unauthorized_access(self, client: TestClient):
        response = client.get("/api/stats")

        assert response.status_code == 401
