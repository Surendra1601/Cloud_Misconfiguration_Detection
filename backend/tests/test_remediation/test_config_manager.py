"""Tests for ConfigManager DynamoDB CRUD operations."""

from unittest.mock import MagicMock

import boto3
import pytest
from moto import mock_aws

from app.pipeline.remediation.config_manager import (
    ConfigManager,
    _item_to_config,
)
from app.pipeline.remediation.models import (
    AutoRemediationConfig,
)

ACCOUNT = "123456789012"
TABLE_NAME = "auto-remediation-config"


def _create_table(session):
    """Create the auto-remediation-config table."""
    ddb = session.resource("dynamodb")
    ddb.create_table(
        TableName=TABLE_NAME,
        KeySchema=[
            {
                "AttributeName": "pk",
                "KeyType": "HASH",
            },
            {
                "AttributeName": "sk",
                "KeyType": "RANGE",
            },
        ],
        AttributeDefinitions=[
            {
                "AttributeName": "pk",
                "AttributeType": "S",
            },
            {
                "AttributeName": "sk",
                "AttributeType": "S",
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )


@pytest.fixture
def config_mgr(aws_credentials):
    """Create ConfigManager with mocked DynamoDB."""
    with mock_aws():
        session = boto3.Session(
            region_name="us-east-1"
        )
        _create_table(session)
        yield ConfigManager(
            session=session,
            table_name=TABLE_NAME,
        )


def _make_config(
    check_id="CHECK_04",
    enabled=True,
    rollback=60,
):
    """Build a test AutoRemediationConfig."""
    return AutoRemediationConfig(
        account_id=ACCOUNT,
        check_id=check_id,
        enabled=enabled,
        rollback_window_minutes=rollback,
        notify_on_action=True,
        approved_by="admin@example.com",
    )


class TestSetConfig:
    """Test creating/updating configs."""

    def test_set_returns_true(self, config_mgr):
        cfg = _make_config()
        assert config_mgr.set_config(cfg) is True

    def test_set_and_get_roundtrip(self, config_mgr):
        cfg = _make_config()
        config_mgr.set_config(cfg)
        result = config_mgr.get_config(
            ACCOUNT, "CHECK_04"
        )
        assert result is not None
        assert result.account_id == ACCOUNT
        assert result.check_id == "CHECK_04"
        assert result.enabled is True
        assert result.rollback_window_minutes == 60

    def test_set_overwrites_existing(
        self, config_mgr
    ):
        config_mgr.set_config(_make_config())
        config_mgr.set_config(
            _make_config(enabled=False)
        )
        result = config_mgr.get_config(
            ACCOUNT, "CHECK_04"
        )
        assert result.enabled is False

    def test_set_custom_rollback(self, config_mgr):
        cfg = _make_config(rollback=120)
        config_mgr.set_config(cfg)
        result = config_mgr.get_config(
            ACCOUNT, "CHECK_04"
        )
        assert result.rollback_window_minutes == 120

    def test_set_approved_at_auto(self, config_mgr):
        cfg = _make_config()
        config_mgr.set_config(cfg)
        result = config_mgr.get_config(
            ACCOUNT, "CHECK_04"
        )
        assert result.approved_at  # auto-set

    def test_set_multiple_checks(self, config_mgr):
        for cid in [
            "CHECK_04",
            "CHECK_07",
            "CHECK_17",
        ]:
            config_mgr.set_config(
                _make_config(check_id=cid)
            )
        configs = config_mgr.list_configs(ACCOUNT)
        assert len(configs) == 3


class TestGetConfig:
    """Test config retrieval."""

    def test_get_existing(self, config_mgr):
        config_mgr.set_config(_make_config())
        result = config_mgr.get_config(
            ACCOUNT, "CHECK_04"
        )
        assert result is not None

    def test_get_missing(self, config_mgr):
        result = config_mgr.get_config(
            ACCOUNT, "CHECK_99"
        )
        assert result is None

    def test_get_wrong_account(self, config_mgr):
        config_mgr.set_config(_make_config())
        result = config_mgr.get_config(
            "999999999999", "CHECK_04"
        )
        assert result is None

    def test_get_preserves_all_fields(
        self, config_mgr
    ):
        cfg = AutoRemediationConfig(
            account_id=ACCOUNT,
            check_id="CHECK_07",
            enabled=True,
            rollback_window_minutes=90,
            notify_on_action=False,
            approved_by="admin@corp.com",
        )
        config_mgr.set_config(cfg)
        result = config_mgr.get_config(
            ACCOUNT, "CHECK_07"
        )
        assert result.rollback_window_minutes == 90
        assert result.notify_on_action is False
        assert (
            result.approved_by == "admin@corp.com"
        )


class TestDeleteConfig:
    """Test config deletion."""

    def test_delete_existing(self, config_mgr):
        config_mgr.set_config(_make_config())
        ok = config_mgr.delete_config(
            ACCOUNT, "CHECK_04"
        )
        assert ok is True
        assert (
            config_mgr.get_config(
                ACCOUNT, "CHECK_04"
            )
            is None
        )

    def test_delete_nonexistent(self, config_mgr):
        # DynamoDB delete is idempotent
        ok = config_mgr.delete_config(
            ACCOUNT, "CHECK_99"
        )
        assert ok is True

    def test_delete_only_target(self, config_mgr):
        config_mgr.set_config(
            _make_config(check_id="CHECK_04")
        )
        config_mgr.set_config(
            _make_config(check_id="CHECK_07")
        )
        config_mgr.delete_config(
            ACCOUNT, "CHECK_04"
        )
        assert (
            config_mgr.get_config(
                ACCOUNT, "CHECK_04"
            )
            is None
        )
        assert (
            config_mgr.get_config(
                ACCOUNT, "CHECK_07"
            )
            is not None
        )


class TestListConfigs:
    """Test listing configs."""

    def test_list_all(self, config_mgr):
        for cid in [
            "CHECK_04",
            "CHECK_07",
            "CHECK_17",
        ]:
            config_mgr.set_config(
                _make_config(check_id=cid)
            )
        results = config_mgr.list_configs(ACCOUNT)
        assert len(results) == 3

    def test_list_empty(self, config_mgr):
        results = config_mgr.list_configs(
            "999999999999"
        )
        assert results == []

    def test_list_enabled_only(self, config_mgr):
        config_mgr.set_config(
            _make_config(
                check_id="CHECK_04", enabled=True
            )
        )
        config_mgr.set_config(
            _make_config(
                check_id="CHECK_07", enabled=False
            )
        )
        config_mgr.set_config(
            _make_config(
                check_id="CHECK_17", enabled=True
            )
        )
        results = config_mgr.list_configs(
            ACCOUNT, enabled_only=True
        )
        assert len(results) == 2
        for c in results:
            assert c.enabled is True

    def test_list_all_disabled(self, config_mgr):
        config_mgr.set_config(
            _make_config(
                check_id="CHECK_04", enabled=False
            )
        )
        results = config_mgr.list_configs(
            ACCOUNT, enabled_only=True
        )
        assert results == []


class TestIsEnabled:
    """Test convenience enabled check."""

    def test_enabled(self, config_mgr):
        config_mgr.set_config(
            _make_config(enabled=True)
        )
        assert (
            config_mgr.is_enabled(
                ACCOUNT, "CHECK_04"
            )
            is True
        )

    def test_disabled(self, config_mgr):
        config_mgr.set_config(
            _make_config(enabled=False)
        )
        assert (
            config_mgr.is_enabled(
                ACCOUNT, "CHECK_04"
            )
            is False
        )

    def test_missing(self, config_mgr):
        assert (
            config_mgr.is_enabled(
                ACCOUNT, "CHECK_99"
            )
            is False
        )


class TestCountEnabled:
    """Test enabled config counting."""

    def test_count_zero(self, config_mgr):
        assert (
            config_mgr.count_enabled(ACCOUNT) == 0
        )

    def test_count_mixed(self, config_mgr):
        config_mgr.set_config(
            _make_config(
                check_id="CHECK_04", enabled=True
            )
        )
        config_mgr.set_config(
            _make_config(
                check_id="CHECK_07", enabled=False
            )
        )
        config_mgr.set_config(
            _make_config(
                check_id="CHECK_17", enabled=True
            )
        )
        assert (
            config_mgr.count_enabled(ACCOUNT) == 2
        )


class TestErrorHandling:
    """Test error handling paths."""

    def test_get_config_error(self, aws_credentials):
        with mock_aws():
            session = boto3.Session(
                region_name="us-east-1"
            )
            _create_table(session)
            mgr = ConfigManager(
                session=session,
                table_name=TABLE_NAME,
            )
            mgr.table = MagicMock()
            mgr.table.get_item.side_effect = (
                Exception("DDB error")
            )
            assert (
                mgr.get_config(ACCOUNT, "C") is None
            )

    def test_set_config_error(self, aws_credentials):
        with mock_aws():
            session = boto3.Session(
                region_name="us-east-1"
            )
            _create_table(session)
            mgr = ConfigManager(
                session=session,
                table_name=TABLE_NAME,
            )
            mgr.table = MagicMock()
            mgr.table.put_item.side_effect = (
                Exception("DDB error")
            )
            assert (
                mgr.set_config(_make_config())
                is False
            )

    def test_delete_config_error(
        self, aws_credentials
    ):
        with mock_aws():
            session = boto3.Session(
                region_name="us-east-1"
            )
            _create_table(session)
            mgr = ConfigManager(
                session=session,
                table_name=TABLE_NAME,
            )
            mgr.table = MagicMock()
            mgr.table.delete_item.side_effect = (
                Exception("DDB error")
            )
            assert (
                mgr.delete_config(ACCOUNT, "C")
                is False
            )

    def test_list_configs_error(
        self, aws_credentials
    ):
        with mock_aws():
            session = boto3.Session(
                region_name="us-east-1"
            )
            _create_table(session)
            mgr = ConfigManager(
                session=session,
                table_name=TABLE_NAME,
            )
            mgr.table = MagicMock()
            mgr.table.query.side_effect = Exception(
                "DDB error"
            )
            assert (
                mgr.list_configs(ACCOUNT) == []
            )


class TestItemToConfig:
    """Test DynamoDB item conversion."""

    def test_basic(self):
        item = {
            "pk": ACCOUNT,
            "sk": "CHECK_04",
            "enabled": True,
            "rollback_window_minutes": 60,
            "notify_on_action": True,
            "approved_by": "admin@example.com",
            "approved_at": "2026-03-01T12:00:00Z",
        }
        cfg = _item_to_config(item)
        assert isinstance(
            cfg, AutoRemediationConfig
        )
        assert cfg.account_id == ACCOUNT
        assert cfg.check_id == "CHECK_04"
        assert cfg.enabled is True

    def test_missing_fields(self):
        item = {"pk": ACCOUNT, "sk": "CHECK_04"}
        cfg = _item_to_config(item)
        assert cfg.enabled is False
        assert cfg.rollback_window_minutes == 60


class TestEndpointUrl:
    """Test endpoint_url branch in __init__."""

    def test_with_endpoint_url(self, aws_credentials):
        with mock_aws():
            session = boto3.Session(
                region_name="us-east-1"
            )
            _create_table(session)
            mgr = ConfigManager(
                session=session,
                table_name=TABLE_NAME,
                endpoint_url=(
                    "http://localhost:8000"
                ),
            )
            assert mgr.table_name == TABLE_NAME
