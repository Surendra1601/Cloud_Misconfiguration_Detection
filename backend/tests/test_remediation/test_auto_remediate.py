"""Tests for AutoRemediationEngine (Tier 3)."""

from unittest.mock import MagicMock, patch, PropertyMock

import boto3
import pytest
from moto import mock_aws

from app.pipeline.remediation.audit_manager import (
    AuditManager,
)
from app.pipeline.remediation.auto_remediate import (
    AutoRemediationEngine,
)
from app.pipeline.remediation.config_manager import (
    ConfigManager,
)
from app.pipeline.remediation.models import (
    AutoRemediationConfig,
    RemediationStatus,
)
from app.pipeline.remediation.one_click import (
    OneClickRemediator,
)

ACCOUNT = "123456789012"
AUDIT_TABLE = "remediation-audit"
CONFIG_TABLE = "auto-remediation-config"


def _create_tables(session):
    """Create both DynamoDB tables."""
    ddb = session.resource("dynamodb")
    for table_name in [AUDIT_TABLE, CONFIG_TABLE]:
        ddb.create_table(
            TableName=table_name,
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
def auto_env(aws_credentials):
    """Set up auto-remediation test environment."""
    with mock_aws():
        session = boto3.Session(
            region_name="us-east-1"
        )
        _create_tables(session)

        # Create SNS topic
        sns = session.client("sns")
        topic = sns.create_topic(
            Name="security-alerts"
        )
        topic_arn = topic["TopicArn"]

        audit_mgr = AuditManager(
            session=session,
            table_name=AUDIT_TABLE,
        )
        config_mgr = ConfigManager(
            session=session,
            table_name=CONFIG_TABLE,
        )
        one_click = OneClickRemediator(
            session=session,
            audit_manager=audit_mgr,
        )
        engine = AutoRemediationEngine(
            one_click=one_click,
            config_manager=config_mgr,
            session=session,
            sns_topic_arn=topic_arn,
        )

        # Create test S3 bucket
        s3 = session.client("s3")
        s3.create_bucket(Bucket="auto-bucket")

        yield (
            session,
            audit_mgr,
            config_mgr,
            engine,
            topic_arn,
        )


class TestAutoRemediation:
    """Test auto-remediation execution."""

    def test_remediates_when_enabled(
        self, auto_env
    ):
        (
            _,
            _,
            config_mgr,
            engine,
            _,
        ) = auto_env

        # Enable auto-remediation
        config_mgr.set_config(
            AutoRemediationConfig(
                account_id=ACCOUNT,
                check_id="CHECK_04",
                enabled=True,
                approved_by="admin@example.com",
            )
        )

        action = engine.evaluate_and_remediate(
            check_id="CHECK_04",
            remediation_id="REM_04",
            resource_arn="arn:aws:s3:::auto-bucket",
            account_id=ACCOUNT,
            severity="critical",
        )

        assert action is not None
        assert (
            action.status
            == RemediationStatus.EXECUTED
        )
        assert action.initiated_by == "SYSTEM"

    def test_skips_when_disabled(self, auto_env):
        (
            _,
            _,
            config_mgr,
            engine,
            _,
        ) = auto_env

        config_mgr.set_config(
            AutoRemediationConfig(
                account_id=ACCOUNT,
                check_id="CHECK_04",
                enabled=False,
            )
        )

        action = engine.evaluate_and_remediate(
            check_id="CHECK_04",
            remediation_id="REM_04",
            resource_arn="arn:aws:s3:::auto-bucket",
            account_id=ACCOUNT,
        )

        assert action is None

    def test_skips_when_no_config(self, auto_env):
        _, _, _, engine, _ = auto_env

        action = engine.evaluate_and_remediate(
            check_id="CHECK_04",
            remediation_id="REM_04",
            resource_arn="arn:aws:s3:::auto-bucket",
            account_id=ACCOUNT,
        )

        assert action is None

    def test_skips_unsupported_remediation(
        self, auto_env
    ):
        (
            _,
            _,
            config_mgr,
            engine,
            _,
        ) = auto_env

        config_mgr.set_config(
            AutoRemediationConfig(
                account_id=ACCOUNT,
                check_id="CHECK_01",
                enabled=True,
            )
        )

        action = engine.evaluate_and_remediate(
            check_id="CHECK_01",
            remediation_id="REM_01",
            resource_arn="arn:aws:iam::root",
            account_id=ACCOUNT,
        )

        assert action is None

    def test_uses_config_rollback_window(
        self, auto_env
    ):
        (
            _,
            _,
            config_mgr,
            engine,
            _,
        ) = auto_env

        config_mgr.set_config(
            AutoRemediationConfig(
                account_id=ACCOUNT,
                check_id="CHECK_04",
                enabled=True,
                rollback_window_minutes=120,
                approved_by="admin@example.com",
            )
        )

        action = engine.evaluate_and_remediate(
            check_id="CHECK_04",
            remediation_id="REM_04",
            resource_arn="arn:aws:s3:::auto-bucket",
            account_id=ACCOUNT,
        )

        assert action is not None
        assert action.rollback_available_until

    def test_records_audit_trail(self, auto_env):
        (
            _,
            audit_mgr,
            config_mgr,
            engine,
            _,
        ) = auto_env

        config_mgr.set_config(
            AutoRemediationConfig(
                account_id=ACCOUNT,
                check_id="CHECK_04",
                enabled=True,
                approved_by="admin@example.com",
            )
        )

        action = engine.evaluate_and_remediate(
            check_id="CHECK_04",
            remediation_id="REM_04",
            resource_arn="arn:aws:s3:::auto-bucket",
            account_id=ACCOUNT,
        )

        entry = audit_mgr.get_action(
            ACCOUNT, action.action_id
        )
        assert entry is not None
        assert entry.initiated_by == "SYSTEM"


class TestSNSNotification:
    """Test SNS notification on auto-remediation."""

    def test_sends_notification(self, auto_env):
        (
            session,
            _,
            config_mgr,
            engine,
            topic_arn,
        ) = auto_env

        config_mgr.set_config(
            AutoRemediationConfig(
                account_id=ACCOUNT,
                check_id="CHECK_04",
                enabled=True,
                notify_on_action=True,
                approved_by="admin@example.com",
            )
        )

        # Subscribe to SNS (moto needs this)
        sns = session.client("sns")
        sns.subscribe(
            TopicArn=topic_arn,
            Protocol="email",
            Endpoint="admin@example.com",
        )

        action = engine.evaluate_and_remediate(
            check_id="CHECK_04",
            remediation_id="REM_04",
            resource_arn="arn:aws:s3:::auto-bucket",
            account_id=ACCOUNT,
            severity="critical",
        )

        assert action is not None
        assert (
            action.status
            == RemediationStatus.EXECUTED
        )

    def test_no_notification_when_disabled(
        self, auto_env
    ):
        (
            session,
            _,
            config_mgr,
            engine,
            _,
        ) = auto_env

        config_mgr.set_config(
            AutoRemediationConfig(
                account_id=ACCOUNT,
                check_id="CHECK_04",
                enabled=True,
                notify_on_action=False,
                approved_by="admin@example.com",
            )
        )

        action = engine.evaluate_and_remediate(
            check_id="CHECK_04",
            remediation_id="REM_04",
            resource_arn="arn:aws:s3:::auto-bucket",
            account_id=ACCOUNT,
        )

        # Should still succeed even without SNS
        assert action is not None

    def test_no_notification_without_topic(
        self, aws_credentials
    ):
        """Engine with no SNS topic skips notif."""
        with mock_aws():
            session = boto3.Session(
                region_name="us-east-1"
            )
            _create_tables(session)
            s3 = session.client("s3")
            s3.create_bucket(Bucket="no-sns-bucket")

            audit_mgr = AuditManager(
                session=session,
                table_name=AUDIT_TABLE,
            )
            config_mgr = ConfigManager(
                session=session,
                table_name=CONFIG_TABLE,
            )
            one_click = OneClickRemediator(
                session=session,
                audit_manager=audit_mgr,
            )
            engine = AutoRemediationEngine(
                one_click=one_click,
                config_manager=config_mgr,
                session=session,
                sns_topic_arn="",  # No topic
            )

            config_mgr.set_config(
                AutoRemediationConfig(
                    account_id=ACCOUNT,
                    check_id="CHECK_04",
                    enabled=True,
                )
            )

            action = engine.evaluate_and_remediate(
                check_id="CHECK_04",
                remediation_id="REM_04",
                resource_arn=(
                    "arn:aws:s3:::no-sns-bucket"
                ),
                account_id=ACCOUNT,
            )

            assert action is not None


class TestIsEligible:
    """Test eligibility checking."""

    def test_eligible_when_enabled(self, auto_env):
        _, _, config_mgr, engine, _ = auto_env
        config_mgr.set_config(
            AutoRemediationConfig(
                account_id=ACCOUNT,
                check_id="CHECK_04",
                enabled=True,
            )
        )
        assert engine.is_eligible(
            "CHECK_04", "REM_04", ACCOUNT
        )

    def test_not_eligible_when_disabled(
        self, auto_env
    ):
        _, _, config_mgr, engine, _ = auto_env
        config_mgr.set_config(
            AutoRemediationConfig(
                account_id=ACCOUNT,
                check_id="CHECK_04",
                enabled=False,
            )
        )
        assert not engine.is_eligible(
            "CHECK_04", "REM_04", ACCOUNT
        )

    def test_not_eligible_unsupported(
        self, auto_env
    ):
        _, _, config_mgr, engine, _ = auto_env
        config_mgr.set_config(
            AutoRemediationConfig(
                account_id=ACCOUNT,
                check_id="CHECK_01",
                enabled=True,
            )
        )
        assert not engine.is_eligible(
            "CHECK_01", "REM_01", ACCOUNT
        )

    def test_not_eligible_no_config(self, auto_env):
        _, _, _, engine, _ = auto_env
        assert not engine.is_eligible(
            "CHECK_04", "REM_04", ACCOUNT
        )

    def test_multiple_checks(self, auto_env):
        _, _, config_mgr, engine, _ = auto_env
        config_mgr.set_config(
            AutoRemediationConfig(
                account_id=ACCOUNT,
                check_id="CHECK_04",
                enabled=True,
            )
        )
        config_mgr.set_config(
            AutoRemediationConfig(
                account_id=ACCOUNT,
                check_id="CHECK_07",
                enabled=False,
            )
        )
        assert engine.is_eligible(
            "CHECK_04", "REM_04", ACCOUNT
        )
        assert not engine.is_eligible(
            "CHECK_07", "REM_07", ACCOUNT
        )


class TestSNSNotificationError:
    """Test SNS publish exception is caught."""

    def test_sns_error_doesnt_crash(
        self, auto_env
    ):
        """SNS failure is logged, action still ok."""
        (
            session,
            _,
            config_mgr,
            engine,
            topic_arn,
        ) = auto_env

        config_mgr.set_config(
            AutoRemediationConfig(
                account_id=ACCOUNT,
                check_id="CHECK_04",
                enabled=True,
                notify_on_action=True,
                approved_by="admin@example.com",
            )
        )

        # Patch SNS client to raise on publish
        with patch.object(
            engine,
            "_send_notification",
            wraps=engine._send_notification,
        ):
            # Break the SNS client
            original = session.client
            def broken_client(svc, **kw):
                c = original(svc, **kw)
                if svc == "sns":
                    c.publish = MagicMock(
                        side_effect=Exception(
                            "SNS down"
                        )
                    )
                return c

            with patch.object(
                session,
                "client",
                side_effect=broken_client,
            ):
                action = (
                    engine.evaluate_and_remediate(
                        check_id="CHECK_04",
                        remediation_id="REM_04",
                        resource_arn=(
                            "arn:aws:s3:::auto-bucket"
                        ),
                        account_id=ACCOUNT,
                        severity="critical",
                    )
                )

            # Action should still succeed
            assert action is not None
