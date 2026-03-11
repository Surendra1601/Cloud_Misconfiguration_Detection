"""Tests for remediation REST API endpoints."""

from pathlib import Path
from unittest.mock import MagicMock

import boto3
import pytest
from fastapi.testclient import TestClient
from moto import mock_aws

from app.dependencies import (
    get_audit_manager,
    get_config_manager,
    get_one_click_remediator,
    get_rollback_manager,
    get_suggestion_manager,
)
from app.main import app
from app.pipeline.remediation.audit_manager import (
    AuditManager,
)
from app.pipeline.remediation.config_manager import (
    ConfigManager,
)
from app.pipeline.remediation.models import (
    AutoRemediationConfig,
    RemediationAction,
    RemediationStatus,
    RemediationTier,
)
from app.pipeline.remediation.one_click import (
    OneClickRemediator,
)
from app.pipeline.remediation.rollback import (
    RollbackManager,
)
from app.pipeline.remediation.suggestions import (
    SuggestionManager,
)

_TEMPLATES_DIR = (
    Path(__file__).parent.parent.parent
    / "app"
    / "pipeline"
    / "remediation"
    / "templates"
)

ACCOUNT = "123456789012"

# Build real SuggestionManager for tests
_real_suggestion_mgr = SuggestionManager(
    template_dir=_TEMPLATES_DIR
)


def _mock_suggestion_mgr():
    return _real_suggestion_mgr


def _mock_audit_mgr():
    mgr = MagicMock(spec=AuditManager)
    mgr.list_actions.return_value = []
    return mgr


def _mock_config_mgr():
    mgr = MagicMock(spec=ConfigManager)
    mgr.list_configs.return_value = []
    mgr.set_config.return_value = True
    return mgr


def _mock_one_click():
    mgr = MagicMock(spec=OneClickRemediator)
    return mgr


def _mock_rollback():
    mgr = MagicMock(spec=RollbackManager)
    return mgr


# Override deps for all tests
app.dependency_overrides[
    get_suggestion_manager
] = _mock_suggestion_mgr
app.dependency_overrides[
    get_audit_manager
] = _mock_audit_mgr
app.dependency_overrides[
    get_config_manager
] = _mock_config_mgr
app.dependency_overrides[
    get_one_click_remediator
] = _mock_one_click
app.dependency_overrides[
    get_rollback_manager
] = _mock_rollback

client = TestClient(app)


class TestGetSuggestion:
    """Test GET /remediation/{id}."""

    def test_get_existing(self):
        resp = client.get(
            "/api/v1/remediation/REM_04"
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["remediation_id"] == "REM_04"
        assert "S3" in data["title"]
        assert "console_steps" in data
        assert "cli_command" in data
        assert "terraform_snippet" in data

    def test_get_cross_resource(self):
        resp = client.get(
            "/api/v1/remediation/REM_CROSS_01"
        )
        assert resp.status_code == 200
        data = resp.json()
        assert (
            data["remediation_id"]
            == "REM_CROSS_01"
        )

    def test_get_not_found(self):
        resp = client.get(
            "/api/v1/remediation/REM_99"
        )
        assert resp.status_code == 404

    def test_includes_references(self):
        resp = client.get(
            "/api/v1/remediation/REM_07"
        )
        data = resp.json()
        assert len(data["references"]) >= 2

    def test_includes_check_id(self):
        resp = client.get(
            "/api/v1/remediation/REM_04"
        )
        data = resp.json()
        assert data["check_id"] == "CHECK_04"


class TestListSuggestions:
    """Test GET /remediation."""

    def test_list_all(self):
        resp = client.get("/api/v1/remediation")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 22
        assert len(data["remediations"]) == 22

    def test_filter_domain(self):
        resp = client.get(
            "/api/v1/remediation"
            "?domain=data_protection"
        )
        data = resp.json()
        assert data["total"] >= 3
        for r in data["remediations"]:
            assert r["domain"] == "data_protection"

    def test_filter_severity(self):
        resp = client.get(
            "/api/v1/remediation"
            "?severity=critical"
        )
        data = resp.json()
        for r in data["remediations"]:
            assert r["severity"] == "critical"

    def test_filter_no_match(self):
        resp = client.get(
            "/api/v1/remediation"
            "?domain=nonexistent"
        )
        data = resp.json()
        assert data["total"] == 0


class TestExecuteRemediation:
    """Test POST /remediation/{id}/execute."""

    def test_execute_success(self):
        mock_oc = _mock_one_click()
        mock_oc.execute.return_value = (
            RemediationAction(
                action_id="rem-001",
                remediation_id="REM_04",
                resource_arn=(
                    "arn:aws:s3:::bucket"
                ),
                account_id=ACCOUNT,
                status=RemediationStatus.EXECUTED,
            )
        )
        app.dependency_overrides[
            get_one_click_remediator
        ] = lambda: mock_oc

        resp = client.post(
            "/api/v1/remediation/REM_04/execute",
            json={
                "resource_arn": (
                    "arn:aws:s3:::bucket"
                ),
                "account_id": ACCOUNT,
                "confirm": True,
            },
        )

        assert resp.status_code == 200
        data = resp.json()
        assert data["action_id"] == "rem-001"
        assert data["status"] == "executed"

        # Restore
        app.dependency_overrides[
            get_one_click_remediator
        ] = _mock_one_click

    def test_execute_no_confirm(self):
        resp = client.post(
            "/api/v1/remediation/REM_04/execute",
            json={
                "resource_arn": (
                    "arn:aws:s3:::bucket"
                ),
                "account_id": ACCOUNT,
                "confirm": False,
            },
        )
        assert resp.status_code == 400

    def test_execute_unsupported(self):
        mock_oc = _mock_one_click()
        mock_oc.execute.side_effect = ValueError(
            "Unsupported"
        )
        app.dependency_overrides[
            get_one_click_remediator
        ] = lambda: mock_oc

        resp = client.post(
            "/api/v1/remediation/REM_01/execute",
            json={
                "resource_arn": "arn:aws:iam::root",
                "account_id": ACCOUNT,
                "confirm": True,
            },
        )
        assert resp.status_code == 400

        app.dependency_overrides[
            get_one_click_remediator
        ] = _mock_one_click


class TestRollback:
    """Test POST /remediation/{id}/rollback."""

    def test_rollback_success(self):
        mock_rb = _mock_rollback()
        mock_rb.rollback.return_value = {
            "status": "rolled_back",
            "action_id": "rem-001",
            "remediation_id": "REM_04",
            "message": "Rolled back",
        }
        app.dependency_overrides[
            get_rollback_manager
        ] = lambda: mock_rb

        resp = client.post(
            "/api/v1/remediation/"
            "REM_04/rollback",
            json={
                "action_id": "rem-001",
                "account_id": ACCOUNT,
            },
        )

        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "rolled_back"

        app.dependency_overrides[
            get_rollback_manager
        ] = _mock_rollback

    def test_rollback_expired(self):
        mock_rb = _mock_rollback()
        mock_rb.rollback.return_value = {
            "status": "error",
            "message": "Rollback window expired",
        }
        app.dependency_overrides[
            get_rollback_manager
        ] = lambda: mock_rb

        resp = client.post(
            "/api/v1/remediation/"
            "REM_04/rollback",
            json={
                "action_id": "rem-001",
                "account_id": ACCOUNT,
            },
        )

        assert resp.status_code == 400

        app.dependency_overrides[
            get_rollback_manager
        ] = _mock_rollback


class TestAuditTrail:
    """Test GET /remediation/audit."""

    def test_list_audit_empty(self):
        resp = client.get(
            "/api/v1/remediation/audit"
            f"?account_id={ACCOUNT}"
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 0
        assert data["entries"] == []

    def test_list_audit_with_filter(self):
        resp = client.get(
            "/api/v1/remediation/audit"
            f"?account_id={ACCOUNT}"
            "&check_id=CHECK_04"
        )
        assert resp.status_code == 200


class TestConfigEndpoints:
    """Test remediation config endpoints."""

    def test_list_configs(self):
        resp = client.get(
            "/api/v1/remediation/config"
            f"?account_id={ACCOUNT}"
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "configs" in data
        assert "total" in data

    def test_set_config(self):
        mock_cm = _mock_config_mgr()
        app.dependency_overrides[
            get_config_manager
        ] = lambda: mock_cm

        resp = client.put(
            "/api/v1/remediation/config",
            json={
                "account_id": ACCOUNT,
                "check_id": "CHECK_04",
                "enabled": True,
                "approved_by": "admin@example.com",
            },
        )

        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "saved"
        assert data["enabled"] is True

        app.dependency_overrides[
            get_config_manager
        ] = _mock_config_mgr

    def test_set_config_failure(self):
        mock_cm = _mock_config_mgr()
        mock_cm.set_config.return_value = False
        app.dependency_overrides[
            get_config_manager
        ] = lambda: mock_cm

        resp = client.put(
            "/api/v1/remediation/config",
            json={
                "account_id": ACCOUNT,
                "check_id": "CHECK_04",
                "enabled": True,
            },
        )

        assert resp.status_code == 500

        app.dependency_overrides[
            get_config_manager
        ] = _mock_config_mgr
