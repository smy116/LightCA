import pytest
from fastapi.testclient import TestClient


class TestKeysAPI:
    """Test keys API endpoints"""

    def test_list_keys_empty(self, client: TestClient, auth_headers: dict):
        response = client.get("/api/keys/list", headers=auth_headers)

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert "data" in data
        assert data["data"]["keys"] == []
        assert data["data"]["total"] == 0

    def test_create_key_rsa_2048(self, client: TestClient, auth_headers: dict):
        response = client.post(
            "/api/keys/create",
            json={
                "algorithm": "RSA",
                "key_size": 2048,
            },
            headers=auth_headers,
        )

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert "key_id" in data["data"]
        assert "fingerprint" in data["data"]
        assert isinstance(data["data"]["key_id"], int)

    def test_create_key_rsa_4096(self, client: TestClient, auth_headers: dict):
        response = client.post(
            "/api/keys/create",
            json={
                "algorithm": "RSA",
                "key_size": 4096,
            },
            headers=auth_headers,
        )

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert "key_id" in data["data"]

    def test_create_key_ecdsa_p256(self, client: TestClient, auth_headers: dict):
        response = client.post(
            "/api/keys/create",
            json={
                "algorithm": "ECDSA",
                "curve": "P-256",
            },
            headers=auth_headers,
        )

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert "key_id" in data["data"]

    def test_create_key_ecdsa_p384(self, client: TestClient, auth_headers: dict):
        response = client.post(
            "/api/keys/create",
            json={
                "algorithm": "ECDSA",
                "curve": "P-384",
            },
            headers=auth_headers,
        )

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert "key_id" in data["data"]

    def test_create_key_ed25519(self, client: TestClient, auth_headers: dict):
        response = client.post(
            "/api/keys/create",
            json={
                "algorithm": "EdDSA",
                "curve": "Ed25519",
            },
            headers=auth_headers,
        )

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert "key_id" in data["data"]

    def test_create_key_with_password(self, client: TestClient, auth_headers: dict):
        response = client.post(
            "/api/keys/create",
            json={
                "algorithm": "RSA",
                "key_size": 2048,
                "password": "key_password",
                "remember_password": True,
            },
            headers=auth_headers,
        )

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert isinstance(data["data"]["key_id"], int)

    def test_create_key_invalid_algorithm(self, client: TestClient, auth_headers: dict):
        response = client.post(
            "/api/keys/create",
            json={
                "algorithm": "INVALID",
            },
            headers=auth_headers,
        )

        assert response.status_code == 422

    def test_create_key_missing_algorithm(self, client: TestClient, auth_headers: dict):
        response = client.post(
            "/api/keys/create",
            json={},
            headers=auth_headers,
        )

        assert response.status_code == 422

    def test_get_key_detail(self, client: TestClient, auth_headers: dict):
        create_response = client.post(
            "/api/keys/create",
            json={
                "algorithm": "RSA",
                "key_size": 2048,
            },
            headers=auth_headers,
        )
        key_id = create_response.json()["data"]["key_id"]

        response = client.get(f"/api/keys/detail?key_id={key_id}", headers=auth_headers)

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["data"]["id"] == key_id
        assert data["data"]["algorithm"] == "RSA"
        assert "fingerprint" in data["data"]

    def test_get_key_not_found(self, client: TestClient, auth_headers: dict):
        response = client.get("/api/keys/detail?key_id=99999", headers=auth_headers)

        assert response.status_code == 404
        data = response.json()
        assert data["success"] is False

    def test_list_keys_paginated(self, client: TestClient, auth_headers: dict):
        for _ in range(5):
            client.post(
                "/api/keys/create",
                json={"algorithm": "RSA", "key_size": 2048},
                headers=auth_headers,
            )

        response = client.get("/api/keys/list?page=1&per_page=3", headers=auth_headers)

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert len(data["data"]["keys"]) == 3
        assert data["data"]["total"] == 5

    def test_list_keys_filter_by_algorithm(self, client: TestClient, auth_headers: dict):
        client.post(
            "/api/keys/create", json={"algorithm": "RSA", "key_size": 2048}, headers=auth_headers
        )
        client.post(
            "/api/keys/create", json={"algorithm": "ECDSA", "curve": "P-256"}, headers=auth_headers
        )
        client.post(
            "/api/keys/create", json={"algorithm": "RSA", "key_size": 4096}, headers=auth_headers
        )

        response = client.get("/api/keys/list?algorithm=RSA", headers=auth_headers)

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert len(data["data"]["keys"]) == 2
        assert all(k["algorithm"] == "RSA" for k in data["data"]["keys"])

    def test_delete_key(self, client: TestClient, auth_headers: dict):
        create_response = client.post(
            "/api/keys/create",
            json={"algorithm": "RSA", "key_size": 2048},
            headers=auth_headers,
        )
        key_id = create_response.json()["data"]["key_id"]

        response = client.post("/api/keys/delete", json={"key_id": key_id}, headers=auth_headers)

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True

    def test_delete_key_not_found(self, client: TestClient, auth_headers: dict):
        response = client.post("/api/keys/delete", json={"key_id": 99999}, headers=auth_headers)

        assert response.status_code == 200

    def test_delete_key_blocked_when_linked_certificate_exists(
        self, client: TestClient, auth_headers: dict
    ):
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
                "subject_dn": "CN=Linked Cert,O=Test Org,C=US",
                "validity_days": 90,
                "is_ca": False,
            },
            headers=auth_headers,
        )
        cert_id = cert_response.json()["data"]["certificate_id"]

        delete_response = client.post(
            "/api/keys/delete", json={"key_id": key_id}, headers=auth_headers
        )

        assert delete_response.status_code == 409
        payload = delete_response.json()
        assert payload["success"] is False
        assert payload["error"]["code"] == "KEY_IN_USE"
        assert payload["data"]["certificate_id"] == cert_id
        assert (
            payload["data"]["certificate_detail_url"]
            == f"/certificates/detail?certificate_id={cert_id}"
        )

    def test_export_key_pem(self, client: TestClient, auth_headers: dict):
        create_response = client.post(
            "/api/keys/create",
            json={"algorithm": "RSA", "key_size": 2048},
            headers=auth_headers,
        )
        key_id = create_response.json()["data"]["key_id"]

        response = client.get(f"/api/keys/export?key_id={key_id}&format=pem", headers=auth_headers)

        assert response.status_code == 200
        assert "application/x-pem-file" in response.headers.get("content-type", "")

    def test_export_key_pkcs12(self, client: TestClient, auth_headers: dict):
        create_response = client.post(
            "/api/keys/create",
            json={"algorithm": "RSA", "key_size": 2048},
            headers=auth_headers,
        )
        key_id = create_response.json()["data"]["key_id"]

        response = client.get(
            f"/api/keys/export?key_id={key_id}&format=pkcs12&password=secret123",
            headers=auth_headers,
        )

        assert response.status_code == 200
        assert "application/x-pkcs12" in response.headers.get("content-type", "")

    def test_export_key_not_found(self, client: TestClient, auth_headers: dict):
        response = client.get("/api/keys/export?key_id=99999&format=pem", headers=auth_headers)

        assert response.status_code == 404

    def test_unauthorized_access(self, client: TestClient):
        response = client.get("/api/keys/list")

        assert response.status_code == 401
