import pytest
from fastapi.testclient import TestClient


class TestCRLAPI:
    """Test CRL API endpoints"""

    def test_list_crls_empty(self, client: TestClient, auth_headers: dict):
        response = client.get("/api/crl/list", headers=auth_headers)

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert "data" in data
        assert data["data"]["crls"] == []

    def test_generate_crl(self, client: TestClient, auth_headers: dict):
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
                "type": "root",
                "subject_dn": "CN=Test Root CA,O=Test Org,C=US",
                "validity_days": 365,
                "is_ca": True,
                "basic_constraints_ca": True,
            },
            headers=auth_headers,
        )
        ca_cert_id = cert_response.json()["data"]["certificate_id"]

        crl_response = client.post(
            "/api/crl/generate",
            json={"ca_id": ca_cert_id},
            headers=auth_headers,
        )

        assert crl_response.status_code == 200
        data = crl_response.json()
        assert data["success"] is True
        assert "crl_id" in data["data"]

    def test_download_crl(self, client: TestClient, auth_headers: dict):
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
                "type": "root",
                "subject_dn": "CN=Test Root CA,O=Test Org,C=US",
                "validity_days": 365,
                "is_ca": True,
                "basic_constraints_ca": True,
            },
            headers=auth_headers,
        )
        ca_cert_id = cert_response.json()["data"]["certificate_id"]

        crl_response = client.post(
            "/api/crl/generate",
            json={"ca_id": ca_cert_id},
            headers=auth_headers,
        )
        crl_id = crl_response.json()["data"]["crl_id"]

        download_response = client.get(
            f"/api/crl/download?crl_id={crl_id}",
            headers=auth_headers,
        )

        assert download_response.status_code == 200

    def test_list_crl_revocations(self, client: TestClient, auth_headers: dict):
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
                "type": "root",
                "subject_dn": "CN=Test Root CA,O=Test Org,C=US",
                "validity_days": 365,
                "is_ca": True,
                "basic_constraints_ca": True,
            },
            headers=auth_headers,
        )
        ca_cert_id = cert_response.json()["data"]["certificate_id"]

        crl_response = client.post(
            "/api/crl/generate",
            json={"ca_id": ca_cert_id},
            headers=auth_headers,
        )
        crl_id = crl_response.json()["data"]["crl_id"]

        list_response = client.get(
            f"/api/crl/revocations?crl_id={crl_id}",
            headers=auth_headers,
        )

        assert list_response.status_code == 200
        data = list_response.json()
        assert data["success"] is True
        assert "revocations" in data["data"]

    def test_unauthorized_access(self, client: TestClient):
        response = client.get("/api/crl/list")

        assert response.status_code == 401
