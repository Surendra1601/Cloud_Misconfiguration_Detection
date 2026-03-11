"""Shared test fixtures."""

import boto3
import pytest
from moto import mock_aws

from app.auth import require_auth, require_operator
from app.config import Settings
from app.main import app

TEST_API_KEY = "test-api-key"


@pytest.fixture
def aws_credentials(monkeypatch):
    """Mock AWS credentials for moto."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")


@pytest.fixture
def mock_session(aws_credentials):
    """Create a moto-mocked boto3 session."""
    with mock_aws():
        session = boto3.Session(region_name="us-east-1")
        yield session


@pytest.fixture
def test_settings():
    """Test application settings."""
    return Settings(
        aws_region="us-east-1",
        aws_account_id="123456789012",
        api_key=TEST_API_KEY,
        app_env="testing",
    )


def _skip_auth():
    """No-op auth override for tests."""
    return "test-token"


def _skip_operator():
    """No-op operator override for tests."""
    return "operator"


@pytest.fixture(autouse=True)
def disable_auth():
    """Disable auth for all tests by default.

    Tests that specifically test auth should
    remove this override.
    """
    app.dependency_overrides[
        require_auth
    ] = _skip_auth
    app.dependency_overrides[
        require_operator
    ] = _skip_operator
    yield
    app.dependency_overrides.pop(
        require_auth, None
    )
    app.dependency_overrides.pop(
        require_operator, None
    )
