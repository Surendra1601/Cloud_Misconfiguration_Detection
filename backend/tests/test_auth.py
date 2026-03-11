"""Tests for authentication and authorization."""

import pytest
from fastapi.testclient import TestClient

from app.auth import require_auth, require_operator
from app.config import settings
from app.main import app

AUTH_HEADER = {
    "Authorization": f"Bearer {settings.api_key}"
}
OPERATOR_HEADERS = {
    **AUTH_HEADER,
    "X-User-Role": "operator",
}
ADMIN_HEADERS = {
    **AUTH_HEADER,
    "X-User-Role": "administrator",
}


class TestRequireAuth:
    """REST API auth enforcement."""

    def setup_method(self):
        app.dependency_overrides.pop(
            require_auth, None
        )
        app.dependency_overrides.pop(
            require_operator, None
        )

    def teardown_method(self):
        app.dependency_overrides.pop(
            require_auth, None
        )
        app.dependency_overrides.pop(
            require_operator, None
        )

    def test_no_token_returns_401(self):
        client = TestClient(app)
        resp = client.get("/api/v1/violations")
        assert resp.status_code == 401

    def test_wrong_token_returns_403(self):
        client = TestClient(app)
        resp = client.get(
            "/api/v1/violations",
            headers={
                "Authorization": "Bearer wrong"
            },
        )
        assert resp.status_code == 403

    def test_valid_token_passes(self):
        client = TestClient(app)
        resp = client.get(
            "/api/v1/compliance/score",
            headers=AUTH_HEADER,
        )
        # Should not be 401/403
        assert resp.status_code not in (401, 403)

    def test_health_no_auth_required(self):
        client = TestClient(app)
        resp = client.get("/health")
        assert resp.status_code == 200

    def test_scans_requires_auth(self):
        client = TestClient(app)
        resp = client.post("/api/v1/scans")
        assert resp.status_code == 401

    def test_drift_requires_auth(self):
        client = TestClient(app)
        resp = client.get(
            "/api/v1/drift/alerts"
        )
        assert resp.status_code == 401

    def test_risk_requires_auth(self):
        client = TestClient(app)
        resp = client.get("/api/v1/risk/scores")
        assert resp.status_code == 401

    def test_remediation_requires_auth(self):
        client = TestClient(app)
        resp = client.get("/api/v1/remediation")
        assert resp.status_code == 401


class TestRequireOperator:
    """RBAC on destructive endpoints."""

    def setup_method(self):
        app.dependency_overrides.pop(
            require_auth, None
        )
        app.dependency_overrides.pop(
            require_operator, None
        )

    def teardown_method(self):
        app.dependency_overrides.pop(
            require_auth, None
        )
        app.dependency_overrides.pop(
            require_operator, None
        )

    def test_execute_without_role_returns_403(
        self,
    ):
        client = TestClient(
            app, raise_server_exceptions=False
        )
        resp = client.post(
            "/api/v1/remediation/REM_04/execute",
            json={
                "resource_arn": "arn:aws:s3:::x",
                "confirm": True,
            },
            headers=AUTH_HEADER,
        )
        assert resp.status_code == 403

    def test_execute_viewer_role_returns_403(self):
        client = TestClient(
            app, raise_server_exceptions=False
        )
        resp = client.post(
            "/api/v1/remediation/REM_04/execute",
            json={
                "resource_arn": "arn:aws:s3:::x",
                "confirm": True,
            },
            headers={
                **AUTH_HEADER,
                "X-User-Role": "viewer",
            },
        )
        assert resp.status_code == 403

    def test_execute_operator_role_passes(self):
        client = TestClient(
            app, raise_server_exceptions=False
        )
        resp = client.post(
            "/api/v1/remediation/REM_04/execute",
            json={
                "resource_arn": "arn:aws:s3:::x",
                "confirm": True,
            },
            headers=OPERATOR_HEADERS,
        )
        # Gets past auth — may fail for other
        # reasons (no DynamoDB)
        assert resp.status_code != 403

    def test_execute_admin_role_passes(self):
        client = TestClient(
            app, raise_server_exceptions=False
        )
        resp = client.post(
            "/api/v1/remediation/REM_04/execute",
            json={
                "resource_arn": "arn:aws:s3:::x",
                "confirm": True,
            },
            headers=ADMIN_HEADERS,
        )
        assert resp.status_code != 403

    def test_rollback_without_role_returns_403(
        self,
    ):
        client = TestClient(
            app, raise_server_exceptions=False
        )
        resp = client.post(
            "/api/v1/remediation/REM_04/rollback",
            json={"action_id": "abc"},
            headers=AUTH_HEADER,
        )
        assert resp.status_code == 403

    def test_rollback_operator_passes(self):
        client = TestClient(
            app, raise_server_exceptions=False
        )
        resp = client.post(
            "/api/v1/remediation/REM_04/rollback",
            json={"action_id": "abc"},
            headers=OPERATOR_HEADERS,
        )
        assert resp.status_code != 403
