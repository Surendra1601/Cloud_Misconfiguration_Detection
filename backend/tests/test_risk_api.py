"""Tests for risk scores REST API endpoints."""

from unittest.mock import MagicMock

from fastapi.testclient import TestClient

from app.dependencies import get_state_manager
from app.main import app
from app.pipeline.models import ViolationState

ACCOUNT = "123456789012"
REGION = "us-east-1"


def _make_state(
    check_id="check_07_security_groups",
    status="alarm",
    severity="critical",
    risk_score=92,
    domain="network",
    resource_arn=(
        "arn:aws:ec2:us-east-1:123:sg/sg-1"
    ),
    reason="Port 22 open to 0.0.0.0/0",
    last_evaluated="2026-03-01T12:00:00Z",
):
    """Build a ViolationState for testing."""
    return ViolationState(
        pk=f"{ACCOUNT}#{REGION}",
        sk=f"{check_id}#{resource_arn}",
        check_id=check_id,
        status=status,
        severity=severity,
        risk_score=risk_score,
        domain=domain,
        resource_arn=resource_arn,
        reason=reason,
        first_detected="2026-03-01T10:00:00Z",
        last_evaluated=last_evaluated,
    )


ALARM_STATES = [
    _make_state(
        check_id="check_07_security_groups",
        risk_score=92,
        severity="critical",
        domain="network",
    ),
    _make_state(
        check_id="check_04_s3_public_access",
        risk_score=75,
        severity="high",
        domain="data_protection",
        resource_arn="arn:aws:s3:::bucket",
    ),
    _make_state(
        check_id="check_03_mfa_all_users",
        risk_score=60,
        severity="medium",
        domain="identity_access",
        resource_arn="arn:aws:iam::123:user/dev",
    ),
    _make_state(
        check_id="check_14_lambda_security",
        risk_score=30,
        severity="low",
        domain="serverless",
        resource_arn="arn:aws:lambda:...:func",
    ),
]


def _mock_state_manager(
    alarm_states=None,
    domain_states=None,
):
    """Create a mock StateManager."""
    mgr = MagicMock()
    mgr.query_by_status.return_value = (
        alarm_states or []
    )
    mgr.query_by_domain.return_value = (
        domain_states or []
    )
    return mgr


class TestRiskScoresEndpoint:
    """GET /api/v1/risk/scores."""

    def setup_method(self):
        self._mock = _mock_state_manager(
            alarm_states=ALARM_STATES,
        )
        app.dependency_overrides[
            get_state_manager
        ] = lambda: self._mock

    def teardown_method(self):
        app.dependency_overrides.pop(
            get_state_manager, None
        )

    def test_returns_200(self):
        client = TestClient(app)
        resp = client.get("/api/v1/risk/scores")
        assert resp.status_code == 200

    def test_returns_all_scores(self):
        client = TestClient(app)
        resp = client.get("/api/v1/risk/scores")
        data = resp.json()
        assert len(data["scores"]) == 4

    def test_response_format(self):
        client = TestClient(app)
        resp = client.get("/api/v1/risk/scores")
        score = resp.json()["scores"][0]
        assert "resource_arn" in score
        assert "check_id" in score
        assert "risk_score" in score
        assert "category" in score
        assert "severity" in score
        assert "domain" in score
        assert "last_evaluated" in score

    def test_min_score_filter(self):
        client = TestClient(app)
        resp = client.get(
            "/api/v1/risk/scores?min_score=70"
        )
        data = resp.json()
        assert len(data["scores"]) == 2
        for s in data["scores"]:
            assert s["risk_score"] >= 70

    def test_category_filter(self):
        client = TestClient(app)
        resp = client.get(
            "/api/v1/risk/scores?category=critical"
        )
        data = resp.json()
        for s in data["scores"]:
            assert s["category"] == "critical"

    def test_domain_filter(self):
        domain_states = [
            _make_state(
                domain="network",
                risk_score=92,
            ),
        ]
        mgr = _mock_state_manager(
            domain_states=domain_states,
        )
        app.dependency_overrides[
            get_state_manager
        ] = lambda: mgr

        client = TestClient(app)
        resp = client.get(
            "/api/v1/risk/scores?domain=network"
        )
        data = resp.json()
        for s in data["scores"]:
            assert s["domain"] == "network"

    def test_limit_param(self):
        client = TestClient(app)
        resp = client.get(
            "/api/v1/risk/scores?limit=2"
        )
        data = resp.json()
        assert len(data["scores"]) <= 2

    def test_combined_filters(self):
        client = TestClient(app)
        resp = client.get(
            "/api/v1/risk/scores"
            "?min_score=50&category=high"
        )
        data = resp.json()
        for s in data["scores"]:
            assert s["risk_score"] >= 50
            assert s["category"] == "high"

    def test_empty_table(self):
        mgr = _mock_state_manager(alarm_states=[])
        app.dependency_overrides[
            get_state_manager
        ] = lambda: mgr

        client = TestClient(app)
        resp = client.get("/api/v1/risk/scores")
        data = resp.json()
        assert data["scores"] == []


class TestRiskSummaryEndpoint:
    """GET /api/v1/risk/summary."""

    def setup_method(self):
        self._mock = _mock_state_manager(
            alarm_states=ALARM_STATES,
        )
        app.dependency_overrides[
            get_state_manager
        ] = lambda: self._mock

    def teardown_method(self):
        app.dependency_overrides.pop(
            get_state_manager, None
        )

    def test_returns_200(self):
        client = TestClient(app)
        resp = client.get("/api/v1/risk/summary")
        assert resp.status_code == 200

    def test_total_scored(self):
        client = TestClient(app)
        resp = client.get("/api/v1/risk/summary")
        data = resp.json()
        assert data["total_scored"] == 4

    def test_by_category_counts(self):
        client = TestClient(app)
        resp = client.get("/api/v1/risk/summary")
        cats = resp.json()["by_category"]
        assert cats["critical"] == 1
        assert cats["high"] == 1
        assert cats["medium"] == 1
        assert cats["low"] == 1

    def test_by_domain_averages(self):
        client = TestClient(app)
        resp = client.get("/api/v1/risk/summary")
        domains = resp.json()["by_domain"]
        assert domains["network"] == 92
        assert domains["data_protection"] == 75

    def test_highest_risk_top5(self):
        client = TestClient(app)
        resp = client.get("/api/v1/risk/summary")
        highest = resp.json()["highest_risk"]
        assert len(highest) <= 5
        assert highest[0]["risk_score"] == 92
        # Sorted descending
        for i in range(len(highest) - 1):
            assert (
                highest[i]["risk_score"]
                >= highest[i + 1]["risk_score"]
            )

    def test_empty_table(self):
        mgr = _mock_state_manager(alarm_states=[])
        app.dependency_overrides[
            get_state_manager
        ] = lambda: mgr

        client = TestClient(app)
        resp = client.get("/api/v1/risk/summary")
        data = resp.json()
        assert data["total_scored"] == 0
        assert data["by_category"] == {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
        }
        assert data["by_domain"] == {}
        assert data["highest_risk"] == []

    def test_summary_format(self):
        client = TestClient(app)
        resp = client.get("/api/v1/risk/summary")
        data = resp.json()
        assert "total_scored" in data
        assert "by_category" in data
        assert "by_domain" in data
        assert "highest_risk" in data
