import io
import zipfile

import pytest
from fastapi.testclient import TestClient


class TestCertificatesAPI:
    """Test certificates API endpoints"""

    def test_list_certificates_empty(self, client: TestClient, auth_headers: dict):
        response = client.get("/api/certificates/list", headers=auth_headers)

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert "data" in data
        assert data["data"]["certificates"] == []
        assert data["data"]["total"] == 0

    def test_create_root_ca_certificate(self, client: TestClient, auth_headers: dict):
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
                "basic_constraints_path_length": None,
            },
            headers=auth_headers,
        )

        assert cert_response.status_code == 200
        data = cert_response.json()
        assert data["success"] is True
        assert "certificate_id" in data["data"]
        assert "serial_number" in data["data"]

        assert isinstance(data["data"]["certificate_id"], int)

    def test_create_root_ca_with_key_config_auto_generate(
        self, client: TestClient, auth_headers: dict
    ):
        cert_response = client.post(
            "/api/certificates/sign",
            json={
                "type": "root",
                "subject_dn": "CN=Auto Root CA,O=Test Org,C=US",
                "validity_days": 365,
                "is_ca": True,
                "key_config": {
                    "algorithm": "RSA",
                    "key_size": 2048,
                },
            },
            headers=auth_headers,
        )

        assert cert_response.status_code == 200
        cert_id = cert_response.json()["data"]["certificate_id"]

        detail_response = client.get(
            f"/api/certificates/detail?certificate_id={cert_id}", headers=auth_headers
        )
        assert detail_response.status_code == 200
        detail = detail_response.json()["data"]
        assert isinstance(detail["key_id"], int)

    def test_create_root_ca_with_protected_key_and_remembered_password(
        self, client: TestClient, auth_headers: dict
    ):
        cert_response = client.post(
            "/api/certificates/sign",
            json={
                "type": "root",
                "subject_dn": "CN=Protected Root CA,O=Test Org,C=US",
                "validity_days": 365,
                "is_ca": True,
                "key_config": {
                    "algorithm": "ECDSA",
                    "curve": "P-256",
                    "password": "test-password",
                    "remember_password": True,
                },
            },
            headers=auth_headers,
        )

        assert cert_response.status_code == 200
        payload = cert_response.json()
        assert payload["success"] is True
        assert isinstance(payload["data"]["certificate_id"], int)

    def test_create_leaf_certificate(self, client: TestClient, auth_headers: dict):
        key_response = client.post(
            "/api/keys/create",
            json={"algorithm": "RSA", "key_size": 2048},
            headers=auth_headers,
        )
        leaf_key_id = key_response.json()["data"]["key_id"]

        ca_key_response = client.post(
            "/api/keys/create",
            json={"algorithm": "RSA", "key_size": 2048},
            headers=auth_headers,
        )
        ca_key_id = ca_key_response.json()["data"]["key_id"]

        ca_cert_response = client.post(
            "/api/certificates/sign",
            json={
                "key_id": ca_key_id,
                "type": "root",
                "subject_dn": "CN=Test Root CA,O=Test Org,C=US",
                "validity_days": 365,
                "is_ca": True,
                "basic_constraints_ca": True,
            },
            headers=auth_headers,
        )
        ca_cert_id = ca_cert_response.json()["data"]["certificate_id"]

        cert_response = client.post(
            "/api/certificates/sign",
            json={
                "key_id": leaf_key_id,
                "type": "leaf",
                "parent_id": ca_cert_id,
                "subject_dn": "CN=Test Server,O=Test Org,C=US",
                "validity_days": 90,
                "is_ca": False,
            },
            headers=auth_headers,
        )

        assert cert_response.status_code == 200
        data = cert_response.json()
        assert data["success"] is True

    def test_get_certificate_detail(self, client: TestClient, auth_headers: dict):
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
            },
            headers=auth_headers,
        )
        cert_id = cert_response.json()["data"]["certificate_id"]

        detail_response = client.get(
            f"/api/certificates/detail?certificate_id={cert_id}", headers=auth_headers
        )

        assert detail_response.status_code == 200
        data = detail_response.json()
        assert data["success"] is True
        assert data["data"]["id"] == cert_id
        assert data["data"]["type"] == "root"
        assert "serial_number" in data["data"]

    def test_get_certificate_not_found(self, client: TestClient, auth_headers: dict):
        response = client.get("/api/certificates/detail?certificate_id=99999", headers=auth_headers)

        assert response.status_code == 404
        data = response.json()
        assert data["success"] is False

    def test_list_certificates_paginated(self, client: TestClient, auth_headers: dict):
        key_response = client.post(
            "/api/keys/create",
            json={"algorithm": "RSA", "key_size": 2048},
            headers=auth_headers,
        )
        key_id = key_response.json()["data"]["key_id"]

        for i in range(5):
            client.post(
                "/api/certificates/sign",
                json={
                    "key_id": key_id,
                    "type": "leaf",
                    "subject_dn": f"CN=Test {i},O=Test Org,C=US",
                    "validity_days": 90,
                    "is_ca": False,
                },
                headers=auth_headers,
            )

        response = client.get("/api/certificates/list?page=1&per_page=3", headers=auth_headers)

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert len(data["data"]["certificates"]) == 3
        assert data["data"]["total"] == 5

    def test_list_certificates_filter_by_status(self, client: TestClient, auth_headers: dict):
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
        cert_id = cert_response.json()["data"]["certificate_id"]

        response = client.get("/api/certificates/list?status=valid", headers=auth_headers)

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True

    def test_revoke_certificate(self, client: TestClient, auth_headers: dict):
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
        cert_id = cert_response.json()["data"]["certificate_id"]

        revoke_response = client.post(
            "/api/certificates/revoke",
            json={"certificate_id": cert_id, "reason": "keyCompromise"},
            headers=auth_headers,
        )

        assert revoke_response.status_code == 200
        data = revoke_response.json()
        assert data["success"] is True

    def test_delete_certificate(self, client: TestClient, auth_headers: dict):
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
                "subject_dn": "CN=Test Cert Cert,O=Test Org,C=US",
                "validity_days": 90,
                "is_ca": False,
            },
            headers=auth_headers,
        )
        cert_id = cert_response.json()["data"]["certificate_id"]

        delete_response = client.post(
            "/api/certificates/delete",
            json={"certificate_id": cert_id},
            headers=auth_headers,
        )

        assert delete_response.status_code == 200
        data = delete_response.json()
        assert data["success"] is True

    def test_export_certificate_pem(self, client: TestClient, auth_headers: dict):
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
        cert_id = cert_response.json()["data"]["certificate_id"]

        export_response = client.get(
            f"/api/certificates/export?certificate_id={cert_id}&format=pem", headers=auth_headers
        )

        assert export_response.status_code == 200

    def test_export_certificate_pkcs12(self, client: TestClient, auth_headers: dict):
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
                "subject_dn": "CN=P12 Cert,O=Test Org,C=US",
                "validity_days": 90,
                "is_ca": False,
            },
            headers=auth_headers,
        )
        cert_id = cert_response.json()["data"]["certificate_id"]

        export_response = client.get(
            f"/api/certificates/export?certificate_id={cert_id}&format=p12&password=secret123",
            headers=auth_headers,
        )

        assert export_response.status_code == 200
        assert "application/x-pkcs12" in export_response.headers.get("content-type", "")

    def test_export_certificate_der(self, client: TestClient, auth_headers: dict):
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
                "subject_dn": "CN=DER Cert,O=Test Org,C=US",
                "validity_days": 90,
                "is_ca": False,
            },
            headers=auth_headers,
        )
        cert_id = cert_response.json()["data"]["certificate_id"]

        export_response = client.get(
            f"/api/certificates/export?certificate_id={cert_id}&format=der", headers=auth_headers
        )

        assert export_response.status_code == 200
        assert "application/x-x509-ca-cert" in export_response.headers.get("content-type", "")

    def test_export_certificate_pem_chain(self, client: TestClient, auth_headers: dict):
        root_key_response = client.post(
            "/api/keys/create",
            json={"algorithm": "RSA", "key_size": 2048},
            headers=auth_headers,
        )
        root_key_id = root_key_response.json()["data"]["key_id"]

        root_cert_response = client.post(
            "/api/certificates/sign",
            json={
                "key_id": root_key_id,
                "type": "root",
                "subject_dn": "CN=Chain Root CA,O=Test Org,C=US",
                "validity_days": 365,
                "is_ca": True,
            },
            headers=auth_headers,
        )
        root_cert_id = root_cert_response.json()["data"]["certificate_id"]

        leaf_key_response = client.post(
            "/api/keys/create",
            json={"algorithm": "RSA", "key_size": 2048},
            headers=auth_headers,
        )
        leaf_key_id = leaf_key_response.json()["data"]["key_id"]

        leaf_cert_response = client.post(
            "/api/certificates/sign",
            json={
                "key_id": leaf_key_id,
                "type": "leaf",
                "parent_id": root_cert_id,
                "subject_dn": "CN=Chain Leaf,O=Test Org,C=US",
                "validity_days": 90,
                "is_ca": False,
            },
            headers=auth_headers,
        )
        leaf_cert_id = leaf_cert_response.json()["data"]["certificate_id"]

        export_response = client.get(
            f"/api/certificates/export?certificate_id={leaf_cert_id}&format=pem-chain",
            headers=auth_headers,
        )

        assert export_response.status_code == 200
        assert "application/zip" in export_response.headers.get("content-type", "")
        assert f"cert_{leaf_cert_id}-chain.zip" in export_response.headers.get(
            "content-disposition", ""
        )

        archive = zipfile.ZipFile(io.BytesIO(export_response.content))
        names = set(archive.namelist())
        assert f"cert_{leaf_cert_id}-chain.pem" in names
        assert f"cert_{leaf_cert_id}.key.pem" in names

        chain_pem = archive.read(f"cert_{leaf_cert_id}-chain.pem").decode()
        key_pem = archive.read(f"cert_{leaf_cert_id}.key.pem").decode()
        assert chain_pem.count("-----BEGIN CERTIFICATE-----") >= 2
        assert "-----BEGIN PRIVATE KEY-----" in key_pem

    def test_export_certificate_pem_bundle(self, client: TestClient, auth_headers: dict):
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
                "subject_dn": "CN=Bundle Cert,O=Test Org,C=US",
                "validity_days": 90,
                "is_ca": False,
            },
            headers=auth_headers,
        )
        cert_id = cert_response.json()["data"]["certificate_id"]

        export_response = client.get(
            f"/api/certificates/export?certificate_id={cert_id}&format=pem-bundle",
            headers=auth_headers,
        )

        assert export_response.status_code == 200
        body_text = export_response.content.decode()
        assert "-----BEGIN CERTIFICATE-----" in body_text
        assert "-----BEGIN PRIVATE KEY-----" in body_text

    def test_export_certificate_p12_without_private_key_returns_404(
        self, client: TestClient, auth_headers: dict
    ):
        root_key_response = client.post(
            "/api/keys/create",
            json={"algorithm": "RSA", "key_size": 2048},
            headers=auth_headers,
        )
        root_key_id = root_key_response.json()["data"]["key_id"]

        root_cert_response = client.post(
            "/api/certificates/sign",
            json={
                "key_id": root_key_id,
                "type": "root",
                "subject_dn": "CN=NoKey Root,O=Test Org,C=US",
                "validity_days": 365,
                "is_ca": True,
            },
            headers=auth_headers,
        )
        root_cert_id = root_cert_response.json()["data"]["certificate_id"]

        leaf_response = client.post(
            "/api/certificates/sign",
            json={
                "issuer_id": root_cert_id,
                "type": "leaf",
                "subject_dn": "CN=NoKey Leaf,O=Test Org,C=US",
                "validity_days": 90,
                "is_ca": False,
            },
            headers=auth_headers,
        )
        assert leaf_response.status_code == 200
        leaf_cert_id = leaf_response.json()["data"]["certificate_id"]

        export_response = client.get(
            f"/api/certificates/export?certificate_id={leaf_cert_id}&format=p12",
            headers=auth_headers,
        )

        assert export_response.status_code == 404

    def test_list_certificates_search_by_ip_in_metadata(
        self, client: TestClient, auth_headers: dict
    ):
        key_response = client.post(
            "/api/keys/create",
            json={"algorithm": "RSA", "key_size": 2048},
            headers=auth_headers,
        )
        key_id = key_response.json()["data"]["key_id"]

        client.post(
            "/api/certificates/sign",
            json={
                "key_id": key_id,
                "type": "leaf",
                "subject_dn": "CN=IP Cert,O=Test Org,C=US",
                "validity_days": 90,
                "extensions": {"san": {"ip": ["10.0.0.10"]}},
                "is_ca": False,
            },
            headers=auth_headers,
        )

        response = client.get("/api/certificates/list?search=10.0.0.10", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["data"]["total"] >= 1

    def test_list_certificates_sort_by_not_after(self, client: TestClient, auth_headers: dict):
        key_response = client.post(
            "/api/keys/create",
            json={"algorithm": "RSA", "key_size": 2048},
            headers=auth_headers,
        )
        key_id = key_response.json()["data"]["key_id"]

        client.post(
            "/api/certificates/sign",
            json={
                "key_id": key_id,
                "type": "leaf",
                "subject_dn": "CN=Short Validity,O=Test Org,C=US",
                "validity_days": 30,
                "is_ca": False,
            },
            headers=auth_headers,
        )
        client.post(
            "/api/certificates/sign",
            json={
                "key_id": key_id,
                "type": "leaf",
                "subject_dn": "CN=Long Validity,O=Test Org,C=US",
                "validity_days": 365,
                "is_ca": False,
            },
            headers=auth_headers,
        )

        response = client.get(
            "/api/certificates/list?sort_by=not_after&sort_order=asc",
            headers=auth_headers,
        )

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        certs = data["data"]["certificates"]
        if len(certs) >= 2:
            assert certs[0]["not_after"] <= certs[1]["not_after"]

    def test_unauthorized_access(self, client: TestClient):
        response = client.get("/api/certificates/list")

        assert response.status_code == 401
