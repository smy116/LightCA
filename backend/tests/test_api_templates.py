import pytest
from fastapi.testclient import TestClient
from app.models.template import Template


class TestTemplatesAPI:
    """Test templates API endpoints"""

    def test_list_templates(self, client: TestClient, auth_headers: dict, db):
        builtin_template = Template(
            name="Built-in Server",
            template_type="leaf",
            key_usage="{}",
            extended_key_usage='{"server_auth": true}',
            policy="{}",
            is_builtin=True,
        )
        db.add(builtin_template)
        db.commit()

        response = client.get("/api/templates/list", headers=auth_headers)

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert "data" in data
        assert isinstance(data["data"]["templates"], list)
        assert any(t["is_builtin"] for t in data["data"]["templates"])

    def test_create_template(self, client: TestClient, auth_headers: dict):
        response = client.post(
            "/api/templates/create",
            json={
                "name": "Custom Template",
                "description": "A custom certificate template",
                "type": "leaf",
                "subject_dn": "CN=${common_name}",
                "validity_days": 365,
                "is_ca": False,
                "basic_constraints_ca": False,
            },
            headers=auth_headers,
        )

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert "template_id" in data["data"]

        assert isinstance(data["data"]["template_id"], int)

    def test_create_template_with_cert_and_key_parameters(
        self, client: TestClient, auth_headers: dict
    ):
        response = client.post(
            "/api/templates/create",
            json={
                "name": "Signing Flow Template",
                "template_type": "leaf",
                "subject_dn": "CN=service.example.com,O=Demo,C=US",
                "validity_days": 180,
                "key_algorithm": "ECDSA",
                "key_curve": "P-256",
                "key_usage": {
                    "digital_signature": True,
                    "key_encipherment": False,
                },
                "extended_key_usage": {
                    "server_auth": True,
                    "client_auth": True,
                },
                "policy": {},
            },
            headers=auth_headers,
        )

        assert response.status_code == 200
        template_id = response.json()["data"]["template_id"]

        detail = client.get(
            f"/api/templates/detail?template_id={template_id}", headers=auth_headers
        )
        assert detail.status_code == 200
        payload = detail.json()["data"]

        assert payload["template_type"] == "leaf"
        assert payload["policy"]["subject_dn"] == "CN=service.example.com,O=Demo,C=US"
        assert payload["policy"]["validity_days"] == 180
        assert payload["policy"]["key_algorithm"] == "ECDSA"
        assert payload["policy"]["key_curve"] == "P-256"
        assert payload["extended_key_usage"]["server_auth"] is True

    def test_create_ca_template(self, client: TestClient, auth_headers: dict):
        response = client.post(
            "/api/templates/create",
            json={
                "name": "Custom CA Template",
                "description": "A custom CA template",
                "type": "root",
                "subject_dn": "CN=${common_name}",
                "validity_days": 3650,
                "is_ca": True,
                "basic_constraints_ca": True,
                "basic_constraints_path_length": None,
            },
            headers=auth_headers,
        )

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True

    def test_get_template_detail(self, client: TestClient, auth_headers: dict):
        create_response = client.post(
            "/api/templates/create",
            json={
                "name": "Test Template",
                "description": "Test template",
                "type": "leaf",
                "subject_dn": "CN=${common_name}",
                "validity_days": 365,
                "is_ca": False,
                "basic_constraints_ca": False,
            },
            headers=auth_headers,
        )
        template_id = create_response.json()["data"]["template_id"]

        response = client.get(
            f"/api/templates/detail?template_id={template_id}", headers=auth_headers
        )

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["data"]["id"] == template_id
        assert data["data"]["name"] == "Test Template"

    def test_update_template(self, client: TestClient, auth_headers: dict):
        create_response = client.post(
            "/api/templates/create",
            json={
                "name": "Original Name",
                "description": "Original description",
                "type": "leaf",
                "subject_dn": "CN=${common_name}",
                "validity_days": 365,
                "is_ca": False,
                "basic_constraints_ca": False,
            },
            headers=auth_headers,
        )
        template_id = create_response.json()["data"]["template_id"]

        response = client.post(
            "/api/templates/update",
            json={
                "template_id": template_id,
                "name": "Updated Name",
                "description": "Updated description",
                "validity_days": 730,
            },
            headers=auth_headers,
        )

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True

    def test_delete_template(self, client: TestClient, auth_headers: dict):
        create_response = client.post(
            "/api/templates/create",
            json={
                "name": "To Delete",
                "description": "This will be deleted",
                "type": "leaf",
                "subject_dn": "CN=${common_name}",
                "validity_days": 365,
                "is_ca": False,
                "basic_constraints_ca": False,
            },
            headers=auth_headers,
        )
        template_id = create_response.json()["data"]["template_id"]

        response = client.post(
            "/api/templates/delete",
            json={"template_id": template_id},
            headers=auth_headers,
        )

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True

    def test_get_template_not_found(self, client: TestClient, auth_headers: dict):
        response = client.get("/api/templates/detail?template_id=99999", headers=auth_headers)

        assert response.status_code == 404
        data = response.json()
        assert data["success"] is False

    def test_unauthorized_access(self, client: TestClient):
        response = client.get("/api/templates/list")

        assert response.status_code == 401
