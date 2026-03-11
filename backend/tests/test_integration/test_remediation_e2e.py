"""End-to-end integration tests for the remediation
pipeline.

Tests the full flow:
1. Suggestion lookup → one-click execute → audit trail
2. Execute → rollback within window
3. Auto-remediation via EventHandler pipeline
4. Config enable/disable cycle

Uses moto for AWS services (DynamoDB, S3, SNS) with
real business logic (no mocking of remediation code).
"""

from pathlib import Path
from unittest.mock import MagicMock

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
    RemediationTier,
)
from app.pipeline.remediation.one_click import (
    OneClickRemediator,
    SUPPORTED_REMEDIATIONS,
)
from app.pipeline.remediation.rollback import (
    RollbackManager,
)
from app.pipeline.remediation.suggestions import (
    SuggestionManager,
)

ACCOUNT = "123456789012"
AUDIT_TABLE = "remediation-audit"
CONFIG_TABLE = "auto-remediation-config"


def _create_tables(session):
    """Create DynamoDB tables for remediation."""
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
def remediation_env(aws_credentials):
    """Full remediation test environment."""
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

        # Create S3 test bucket
        s3 = session.client("s3")
        s3.create_bucket(Bucket="e2e-bucket")

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
        rollback_mgr = RollbackManager(
            session=session,
            audit_manager=audit_mgr,
        )
        auto_engine = AutoRemediationEngine(
            one_click=one_click,
            config_manager=config_mgr,
            session=session,
            sns_topic_arn=topic_arn,
        )
        suggestion_mgr = SuggestionManager()

        yield {
            "session": session,
            "audit_mgr": audit_mgr,
            "config_mgr": config_mgr,
            "one_click": one_click,
            "rollback_mgr": rollback_mgr,
            "auto_engine": auto_engine,
            "suggestion_mgr": suggestion_mgr,
            "topic_arn": topic_arn,
        }


class TestSuggestionToExecuteFlow:
    """Tier 1 → Tier 2: lookup then execute."""

    def test_lookup_then_execute_s3(
        self, remediation_env
    ):
        """Full flow: get suggestion → execute fix."""
        env = remediation_env
        suggestion = env[
            "suggestion_mgr"
        ].get_suggestion("REM_04")
        assert suggestion.remediation_id == "REM_04"
        assert suggestion.check_id == "CHECK_04"

        # Execute one-click fix
        action = env["one_click"].execute(
            remediation_id="REM_04",
            resource_arn="arn:aws:s3:::e2e-bucket",
            account_id=ACCOUNT,
            initiated_by="e2e-test",
        )

        assert (
            action.status
            == RemediationStatus.EXECUTED
        )
        assert action.remediation_id == "REM_04"
        assert action.account_id == ACCOUNT

        # Verify S3 public access block is set
        s3 = env["session"].client("s3")
        config = s3.get_public_access_block(
            Bucket="e2e-bucket"
        )
        pab = config[
            "PublicAccessBlockConfiguration"
        ]
        assert pab["BlockPublicAcls"] is True
        assert pab["BlockPublicPolicy"] is True
        assert pab["IgnorePublicAcls"] is True
        assert (
            pab["RestrictPublicBuckets"] is True
        )

    def test_execute_creates_audit_entry(
        self, remediation_env
    ):
        """Execution recorded in audit trail."""
        env = remediation_env
        action = env["one_click"].execute(
            remediation_id="REM_04",
            resource_arn="arn:aws:s3:::e2e-bucket",
            account_id=ACCOUNT,
            initiated_by="e2e-test",
        )

        entry = env["audit_mgr"].get_action(
            ACCOUNT, action.action_id
        )
        assert entry is not None
        assert entry.remediation_id == "REM_04"
        assert entry.initiated_by == "e2e-test"
        assert entry.tier == RemediationTier.ONE_CLICK
        assert (
            entry.status
            == RemediationStatus.EXECUTED
        )


class TestExecuteAndRollbackFlow:
    """Execute → rollback full cycle."""

    def test_execute_then_rollback_s3(
        self, remediation_env
    ):
        """Execute S3 fix, then roll it back."""
        env = remediation_env

        # Execute
        action = env["one_click"].execute(
            remediation_id="REM_04",
            resource_arn="arn:aws:s3:::e2e-bucket",
            account_id=ACCOUNT,
            initiated_by="e2e-test",
        )
        assert (
            action.status
            == RemediationStatus.EXECUTED
        )

        # Verify fix was applied
        s3 = env["session"].client("s3")
        config = s3.get_public_access_block(
            Bucket="e2e-bucket"
        )
        pab = config[
            "PublicAccessBlockConfiguration"
        ]
        assert pab["BlockPublicAcls"] is True

        # Rollback
        result = env["rollback_mgr"].rollback(
            action_id=action.action_id,
            account_id=ACCOUNT,
        )
        assert result["status"] == "rolled_back"

        # Verify audit trail shows rollback
        entry = env["audit_mgr"].get_action(
            ACCOUNT, action.action_id
        )
        assert (
            entry.status
            == RemediationStatus.ROLLED_BACK
        )


class TestAutoRemediationFlow:
    """Config → auto-remediate → audit trail."""

    def test_enable_config_then_auto_remediate(
        self, remediation_env
    ):
        """Enable auto-remediation, then trigger it."""
        env = remediation_env

        # Step 1: Enable auto-remediation
        env["config_mgr"].set_config(
            AutoRemediationConfig(
                account_id=ACCOUNT,
                check_id="CHECK_04",
                enabled=True,
                approved_by="admin@example.com",
            )
        )

        # Step 2: Run auto-remediation engine
        action = env[
            "auto_engine"
        ].evaluate_and_remediate(
            check_id="CHECK_04",
            remediation_id="REM_04",
            resource_arn=(
                "arn:aws:s3:::e2e-bucket"
            ),
            account_id=ACCOUNT,
            severity="critical",
        )

        # Step 3: Verify execution
        assert action is not None
        assert (
            action.status
            == RemediationStatus.EXECUTED
        )
        assert action.initiated_by == "SYSTEM"

        # Step 4: Verify audit trail
        entry = env["audit_mgr"].get_action(
            ACCOUNT, action.action_id
        )
        assert entry is not None
        assert entry.initiated_by == "SYSTEM"

    def test_disabled_config_skips(
        self, remediation_env
    ):
        """Disabled config prevents execution."""
        env = remediation_env

        env["config_mgr"].set_config(
            AutoRemediationConfig(
                account_id=ACCOUNT,
                check_id="CHECK_04",
                enabled=False,
            )
        )

        action = env[
            "auto_engine"
        ].evaluate_and_remediate(
            check_id="CHECK_04",
            remediation_id="REM_04",
            resource_arn=(
                "arn:aws:s3:::e2e-bucket"
            ),
            account_id=ACCOUNT,
        )

        assert action is None

    def test_config_toggle_cycle(
        self, remediation_env
    ):
        """Enable → disable → verify skip."""
        env = remediation_env

        # Enable
        env["config_mgr"].set_config(
            AutoRemediationConfig(
                account_id=ACCOUNT,
                check_id="CHECK_04",
                enabled=True,
                approved_by="admin@example.com",
            )
        )
        assert env["config_mgr"].is_enabled(
            ACCOUNT, "CHECK_04"
        )

        # Disable
        env["config_mgr"].set_config(
            AutoRemediationConfig(
                account_id=ACCOUNT,
                check_id="CHECK_04",
                enabled=False,
            )
        )
        assert not env["config_mgr"].is_enabled(
            ACCOUNT, "CHECK_04"
        )

        # Verify engine respects disabled config
        action = env[
            "auto_engine"
        ].evaluate_and_remediate(
            check_id="CHECK_04",
            remediation_id="REM_04",
            resource_arn=(
                "arn:aws:s3:::e2e-bucket"
            ),
            account_id=ACCOUNT,
        )
        assert action is None


class TestAutoRemediateWithSNS:
    """Auto-remediation with SNS notification."""

    def test_full_flow_with_notification(
        self, remediation_env
    ):
        """Execute auto-fix and send SNS alert."""
        env = remediation_env

        # Subscribe to topic
        sns = env["session"].client("sns")
        sns.subscribe(
            TopicArn=env["topic_arn"],
            Protocol="email",
            Endpoint="admin@example.com",
        )

        # Enable auto-remediation with notify
        env["config_mgr"].set_config(
            AutoRemediationConfig(
                account_id=ACCOUNT,
                check_id="CHECK_04",
                enabled=True,
                notify_on_action=True,
                approved_by="admin@example.com",
            )
        )

        action = env[
            "auto_engine"
        ].evaluate_and_remediate(
            check_id="CHECK_04",
            remediation_id="REM_04",
            resource_arn=(
                "arn:aws:s3:::e2e-bucket"
            ),
            account_id=ACCOUNT,
            severity="critical",
        )

        assert action is not None
        assert (
            action.status
            == RemediationStatus.EXECUTED
        )


class TestMultipleRemediations:
    """Test multiple remediations on same account."""

    def test_two_remediations_same_account(
        self, remediation_env
    ):
        """Execute two different remediations."""
        env = remediation_env
        session = env["session"]

        # Create CloudTrail trail
        ct = session.client("cloudtrail")
        s3 = session.client("s3")
        s3.create_bucket(Bucket="trail-bucket")
        ct.create_trail(
            Name="e2e-trail",
            S3BucketName="trail-bucket",
        )

        # Execute S3 fix
        s3_action = env["one_click"].execute(
            remediation_id="REM_04",
            resource_arn=(
                "arn:aws:s3:::e2e-bucket"
            ),
            account_id=ACCOUNT,
            initiated_by="e2e-test",
        )
        assert (
            s3_action.status
            == RemediationStatus.EXECUTED
        )

        # Execute CloudTrail fix
        ct_action = env["one_click"].execute(
            remediation_id="REM_05",
            resource_arn=(
                "arn:aws:cloudtrail:us-east-1:"
                f"{ACCOUNT}:trail/e2e-trail"
            ),
            account_id=ACCOUNT,
            initiated_by="e2e-test",
        )
        assert (
            ct_action.status
            == RemediationStatus.EXECUTED
        )

        # Verify both in audit trail
        entries = env["audit_mgr"].list_actions(
            account_id=ACCOUNT
        )
        assert len(entries) == 2
        rem_ids = {
            e.remediation_id for e in entries
        }
        assert rem_ids == {"REM_04", "REM_05"}


class TestSuggestionCoverage:
    """Verify suggestion templates cover all checks."""

    def test_all_22_templates_load(
        self, remediation_env
    ):
        """All 22 templates available."""
        mgr = remediation_env["suggestion_mgr"]
        templates = mgr.list_suggestions()
        assert len(templates) == 22

    def test_supported_have_templates(
        self, remediation_env
    ):
        """Every supported one-click has a template."""
        mgr = remediation_env["suggestion_mgr"]
        for rem_id in SUPPORTED_REMEDIATIONS:
            template = mgr.get_suggestion(rem_id)
            assert template is not None
            assert template.cli_command != ""

    def test_each_domain_has_suggestions(
        self, remediation_env
    ):
        """All 5 security domains represented."""
        mgr = remediation_env["suggestion_mgr"]
        domains = mgr.get_domains()
        expected = {
            "identity_access",
            "data_protection",
            "network",
            "logging_monitoring",
            "detection",
        }
        assert expected.issubset(set(domains))


class TestAuditTrailIntegrity:
    """Audit trail consistency checks."""

    def test_audit_count_increments(
        self, remediation_env
    ):
        """Count increments with each action."""
        env = remediation_env
        assert (
            env["audit_mgr"].count_actions(ACCOUNT)
            == 0
        )

        env["one_click"].execute(
            remediation_id="REM_04",
            resource_arn=(
                "arn:aws:s3:::e2e-bucket"
            ),
            account_id=ACCOUNT,
            initiated_by="test1",
        )
        assert (
            env["audit_mgr"].count_actions(ACCOUNT)
            == 1
        )

        env["one_click"].execute(
            remediation_id="REM_04",
            resource_arn=(
                "arn:aws:s3:::e2e-bucket"
            ),
            account_id=ACCOUNT,
            initiated_by="test2",
        )
        assert (
            env["audit_mgr"].count_actions(ACCOUNT)
            == 2
        )

    def test_filter_by_check_id(
        self, remediation_env
    ):
        """Audit filtered by check_id."""
        env = remediation_env

        env["one_click"].execute(
            remediation_id="REM_04",
            resource_arn=(
                "arn:aws:s3:::e2e-bucket"
            ),
            account_id=ACCOUNT,
            initiated_by="test",
        )

        # Filter by the correct check_id
        entries = env["audit_mgr"].list_actions(
            account_id=ACCOUNT,
            check_id="CHECK_04",
        )
        assert len(entries) == 1

        # Filter by wrong check_id
        entries = env["audit_mgr"].list_actions(
            account_id=ACCOUNT,
            check_id="CHECK_99",
        )
        assert len(entries) == 0
