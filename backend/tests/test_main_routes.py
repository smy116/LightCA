from fastapi import Query
from fastapi.testclient import TestClient


class TestMainRoutes:
    def test_frontend_pages_render(self, client: TestClient):
        routes = [
            "/login",
            "/",
            "/ca",
            "/ca/detail",
            "/ca/tree",
            "/certificates",
            "/certificates/sign",
            "/certificates/import",
            "/certificates/detail",
            "/keys",
            "/templates",
            "/templates/create",
            "/templates/detail",
            "/crl",
            "/crl/revocations",
        ]

        for path in routes:
            response = client.get(path)
            assert response.status_code == 200
            assert "text/html" in response.headers.get("content-type", "")

    def test_http_exception_handler_shape(self, client: TestClient, auth_headers: dict):
        response = client.get("/api/keys/detail", headers=auth_headers)
        assert response.status_code == 422
        body = response.json()
        assert body["success"] is False
        assert "message" in body
        assert "error" in body

    def test_sign_page_contains_terminal_certificate_wording(self, client: TestClient):
        response = client.get("/certificates/sign")
        assert response.status_code == 200
        html = response.text
        assert "终端证书" in html
        assert "叶证书" not in html

    def test_certificate_detail_page_contains_all_export_formats(self, client: TestClient):
        response = client.get("/certificates/detail")
        assert response.status_code == 200
        html = response.text
        assert "PEM - 标准 PEM 格式证书" in html
        assert "PEM Chain - 完整证书链" in html
        assert "PEM Bundle - 链 + 证书 + 私钥" in html
        assert "DER - 二进制格式" in html
        assert "PKCS#12 - .p12 (证书 + 私钥)" in html

    def test_validation_exception_handler_shape(self, client: TestClient, auth_headers: dict):
        response = client.get(
            "/api/keys/export",
            params={"key_id": 0, "format": "bad"},
            headers=auth_headers,
        )
        assert response.status_code == 422
        body = response.json()
        assert body["success"] is False
        assert body["error"]["code"] == "VALIDATION_ERROR"

    def test_general_exception_handler_shape(self, client: TestClient):
        from app.main import app

        @app.get("/__test_raise_internal")
        async def _raise_internal(force: int = Query(...)):  # pragma: no cover
            raise RuntimeError("boom")

        local_client = TestClient(app, raise_server_exceptions=False)
        response = local_client.get("/__test_raise_internal", params={"force": 1})
        assert response.status_code == 500
        body = response.json()
        assert body["success"] is False
        assert body["error"]["code"] == "INTERNAL_ERROR"
