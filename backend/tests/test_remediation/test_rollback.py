"""Tests for RollbackManager."""

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

import boto3
import pytest
from moto import mock_aws

from app.pipeline.remediation.audit_manager import (
    AuditManager,
)
from app.pipeline.remediation.models import (
    RemediationStatus,
    RemediationTier,
)
from app.pipeline.remediation.one_click import (
    OneClickRemediator,
)
from app.pipeline.remediation.rollback import (
    RollbackManager,
    _ROLLBACK_HANDLERS,
    _rollback_cloudtrail,
    _rollback_imdsv2,
    _rollback_s3_public_access,
    _rollback_security_group,
)

ACCOUNT = "123456789012"
AUDIT_TABLE = "remediation-audit"


def _create_audit_table(session):
    """Create the remediation-audit table."""
    ddb = session.resource("dynamodb")
    ddb.create_table(
        TableName=AUDIT_TABLE,
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
def rollback_env(aws_credentials):
    """Set up rollback test environment."""
    with mock_aws():
        session = boto3.Session(
            region_name="us-east-1"
        )
        _create_audit_table(session)
        audit_mgr = AuditManager(
            session=session,
            table_name=AUDIT_TABLE,
        )
        remediator = OneClickRemediator(
            session=session,
            audit_manager=audit_mgr,
        )
        rollback_mgr = RollbackManager(
            session=session,
            audit_manager=audit_mgr,
        )
        yield (
            session,
            audit_mgr,
            remediator,
            rollback_mgr,
        )


class TestRollbackS3:
    """Test rollback of S3 public access block."""

    def test_rollback_restores_state(
        self, rollback_env
    ):
        (
            session,
            audit_mgr,
            remediator,
            rollback_mgr,
        ) = rollback_env
        s3 = session.client("s3")
        s3.create_bucket(Bucket="rb-bucket")

        # Apply fix
        action = remediator.execute(
            remediation_id="REM_04",
            resource_arn="arn:aws:s3:::rb-bucket",
            account_id=ACCOUNT,
            initiated_by="user@example.com",
        )

        # Verify fix applied
        resp = s3.get_public_access_block(
            Bucket="rb-bucket"
        )
        assert (
            resp["PublicAccessBlockConfiguration"][
                "BlockPublicAcls"
            ]
            is True
        )

        # Rollback
        result = rollback_mgr.rollback(
            action.action_id, ACCOUNT
        )
        assert result["status"] == "rolled_back"

    def test_rollback_marks_audit_rolled_back(
        self, rollback_env
    ):
        (
            session,
            audit_mgr,
            remediator,
            rollback_mgr,
        ) = rollback_env
        s3 = session.client("s3")
        s3.create_bucket(Bucket="audit-rb")

        action = remediator.execute(
            remediation_id="REM_04",
            resource_arn="arn:aws:s3:::audit-rb",
            account_id=ACCOUNT,
            initiated_by="user@example.com",
        )

        rollback_mgr.rollback(
            action.action_id, ACCOUNT
        )

        entry = audit_mgr.get_action(
            ACCOUNT, action.action_id
        )
        assert (
            entry.status
            == RemediationStatus.ROLLED_BACK
        )


class TestRollbackSecurityGroup:
    """Test rollback of SG SSH removal."""

    def _create_sg(self, session):
        ec2 = session.client("ec2")
        vpc = ec2.create_vpc(
            CidrBlock="10.0.0.0/16"
        )
        sg = ec2.create_security_group(
            GroupName="test-sg",
            Description="Test",
            VpcId=vpc["Vpc"]["VpcId"],
        )
        sg_id = sg["GroupId"]
        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [
                        {"CidrIp": "0.0.0.0/0"}
                    ],
                }
            ],
        )
        return sg_id

    def test_rollback_restores_ssh_rule(
        self, rollback_env
    ):
        (
            session,
            audit_mgr,
            remediator,
            rollback_mgr,
        ) = rollback_env
        sg_id = self._create_sg(session)

        action = remediator.execute(
            remediation_id="REM_07",
            resource_arn=(
                f"arn:aws:ec2:us-east-1:"
                f"{ACCOUNT}:security-group/"
                f"{sg_id}"
            ),
            account_id=ACCOUNT,
            initiated_by="user@example.com",
        )

        result = rollback_mgr.rollback(
            action.action_id, ACCOUNT
        )
        assert result["status"] == "rolled_back"

        # Verify SSH rule restored
        ec2 = session.client("ec2")
        resp = ec2.describe_security_groups(
            GroupIds=[sg_id]
        )
        rules = resp["SecurityGroups"][0][
            "IpPermissions"
        ]
        has_ssh = any(
            r.get("FromPort") == 22
            and any(
                ip.get("CidrIp") == "0.0.0.0/0"
                for ip in r.get("IpRanges", [])
            )
            for r in rules
        )
        assert has_ssh


class TestRollbackEBS:
    """Test rollback of EBS encryption."""

    def test_rollback_disables_encryption(
        self, rollback_env
    ):
        (
            session,
            _,
            remediator,
            rollback_mgr,
        ) = rollback_env

        action = remediator.execute(
            remediation_id="REM_17",
            resource_arn=(
                f"arn:aws:ec2:us-east-1:{ACCOUNT}"
            ),
            account_id=ACCOUNT,
            initiated_by="user@example.com",
        )

        result = rollback_mgr.rollback(
            action.action_id, ACCOUNT
        )
        assert result["status"] == "rolled_back"


class TestRollbackValidation:
    """Test rollback error handling."""

    def test_action_not_found(self, rollback_env):
        _, _, _, rollback_mgr = rollback_env
        result = rollback_mgr.rollback(
            "nonexistent", ACCOUNT
        )
        assert result["status"] == "error"
        assert "not found" in result["message"]

    def test_already_rolled_back(
        self, rollback_env
    ):
        (
            session,
            audit_mgr,
            remediator,
            rollback_mgr,
        ) = rollback_env
        s3 = session.client("s3")
        s3.create_bucket(Bucket="double-rb")

        action = remediator.execute(
            remediation_id="REM_04",
            resource_arn="arn:aws:s3:::double-rb",
            account_id=ACCOUNT,
            initiated_by="user@example.com",
        )

        # First rollback
        rollback_mgr.rollback(
            action.action_id, ACCOUNT
        )
        # Second rollback
        result = rollback_mgr.rollback(
            action.action_id, ACCOUNT
        )
        assert result["status"] == "error"
        assert (
            "Already rolled back"
            in result["message"]
        )

    def test_expired_window(self, rollback_env):
        (
            session,
            audit_mgr,
            _,
            rollback_mgr,
        ) = rollback_env

        # Record action with past rollback deadline
        past = (
            datetime.now(UTC) - timedelta(hours=2)
        )
        action_id = audit_mgr.record_action(
            account_id=ACCOUNT,
            remediation_id="REM_04",
            check_id="CHECK_04",
            resource_arn="arn:aws:s3:::expired",
            action_taken="Fix",
            tier=RemediationTier.ONE_CLICK,
            initiated_by="user@example.com",
            rollback_window_minutes=0,
        )

        # Manually set past deadline
        items = audit_mgr.list_actions(ACCOUNT)
        for item in items:
            if item.action_id == action_id:
                sk = (
                    f"{item.created_at}"
                    f"#{item.remediation_id}"
                )
                audit_mgr.table.update_item(
                    Key={"pk": ACCOUNT, "sk": sk},
                    UpdateExpression=(
                        "SET rollback_deadline "
                        "= :d"
                    ),
                    ExpressionAttributeValues={
                        ":d": past.isoformat()
                    },
                )
                break

        result = rollback_mgr.rollback(
            action_id, ACCOUNT
        )
        assert result["status"] == "error"
        assert "expired" in result["message"]

    def test_unsupported_remediation_rollback(
        self, rollback_env
    ):
        _, audit_mgr, _, rollback_mgr = rollback_env

        # Record action for unsupported remediation
        action_id = audit_mgr.record_action(
            account_id=ACCOUNT,
            remediation_id="REM_01",
            check_id="CHECK_01",
            resource_arn="arn:aws:iam::root",
            action_taken="Manual fix",
            tier=RemediationTier.SUGGESTION,
            initiated_by="user@example.com",
        )

        result = rollback_mgr.rollback(
            action_id, ACCOUNT
        )
        assert result["status"] == "error"
        assert "No rollback handler" in (
            result["message"]
        )


class TestRollbackHandlers:
    """Test rollback handler registry."""

    def test_has_six_handlers(self):
        assert len(_ROLLBACK_HANDLERS) == 6

    def test_rem_04_handler(self):
        assert "REM_04" in _ROLLBACK_HANDLERS

    def test_rem_05_handler(self):
        assert "REM_05" in _ROLLBACK_HANDLERS

    def test_rem_07_handler(self):
        assert "REM_07" in _ROLLBACK_HANDLERS

    def test_rem_08_handler(self):
        assert "REM_08" in _ROLLBACK_HANDLERS

    def test_rem_17_handler(self):
        assert "REM_17" in _ROLLBACK_HANDLERS


class TestRollbackCloudTrail:
    """Test CloudTrail rollback handler directly."""

    def test_rollback_cloudtrail_restores(
        self, rollback_env
    ):
        (
            session,
            audit_mgr,
            remediator,
            rollback_mgr,
        ) = rollback_env
        s3 = session.client("s3")
        s3.create_bucket(Bucket="ct-trail-bucket")
        ct = session.client("cloudtrail")
        ct.create_trail(
            Name="rb-trail",
            S3BucketName="ct-trail-bucket",
        )

        # Execute CloudTrail fix
        action = remediator.execute(
            remediation_id="REM_05",
            resource_arn=(
                "arn:aws:cloudtrail:us-east-1:"
                f"{ACCOUNT}:trail/rb-trail"
            ),
            account_id=ACCOUNT,
            initiated_by="test",
        )

        # Rollback
        result = rollback_mgr.rollback(
            action.action_id, ACCOUNT
        )
        assert result["status"] == "rolled_back"

        # Verify trail restored
        resp = ct.get_trail(Name="rb-trail")
        assert (
            resp["Trail"]["IsMultiRegionTrail"]
            is False
        )


class TestRollbackS3EmptyPreState:
    """Test S3 rollback with empty pre_state."""

    def test_delete_public_access_block(
        self, rollback_env
    ):
        """Empty pre_state → delete_public_access_block."""
        session, _, _, _ = rollback_env
        s3 = session.client("s3")
        s3.create_bucket(Bucket="empty-pre")
        s3.put_public_access_block(
            Bucket="empty-pre",
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )

        # Call rollback with empty pre_state
        _rollback_s3_public_access(
            session,
            "arn:aws:s3:::empty-pre",
            {},
        )

        # Should have deleted the block
        with pytest.raises(Exception):
            s3.get_public_access_block(
                Bucket="empty-pre"
            )


class TestRollbackFailure:
    """Test rollback handler exception path."""

    def test_rollback_handler_exception(
        self, rollback_env
    ):
        (
            session,
            audit_mgr,
            remediator,
            rollback_mgr,
        ) = rollback_env
        s3 = session.client("s3")
        s3.create_bucket(Bucket="fail-rb")

        action = remediator.execute(
            remediation_id="REM_04",
            resource_arn="arn:aws:s3:::fail-rb",
            account_id=ACCOUNT,
            initiated_by="test",
        )

        # Patch handler to raise
        with patch.dict(
            _ROLLBACK_HANDLERS,
            {
                "REM_04": MagicMock(
                    side_effect=RuntimeError(
                        "AWS down"
                    )
                ),
            },
        ):
            result = rollback_mgr.rollback(
                action.action_id, ACCOUNT
            )

        assert result["status"] == "error"
        assert "Rollback failed" in (
            result["message"]
        )


class TestRollbackIMDSv2Direct:
    """Test _rollback_imdsv2 directly with mocks."""

    def test_restores_metadata_options(self):
        """Call _rollback_imdsv2 with mocked EC2."""
        mock_session = MagicMock()
        mock_ec2 = MagicMock()
        mock_session.client.return_value = mock_ec2

        _rollback_imdsv2(
            mock_session,
            "arn:aws:ec2:us-east-1:"
            "123456789012:instance/i-abc",
            {
                "HttpTokens": "optional",
                "HttpEndpoint": "enabled",
            },
        )

        mock_ec2.modify_instance_metadata_options.assert_called_once_with(
            InstanceId="i-abc",
            HttpTokens="optional",
            HttpEndpoint="enabled",
        )


class TestRollbackSGExceptionPath:
    """Test SG rollback when rule already exists."""

    def test_sg_authorize_duplicate_caught(self):
        """Duplicate rule ClientError is caught."""
        from botocore.exceptions import ClientError

        mock_session = MagicMock()
        mock_ec2 = MagicMock()
        mock_session.client.return_value = mock_ec2

        # Simulate duplicate rule ClientError
        mock_ec2.authorize_security_group_ingress.side_effect = (
            ClientError(
                {
                    "Error": {
                        "Code": "InvalidPermission"
                        ".Duplicate",
                        "Message": (
                            "Duplicate rule"
                        ),
                    }
                },
                "AuthorizeSecurityGroupIngress",
            )
        )

        # Should NOT raise — Duplicate is caught
        _rollback_security_group(
            mock_session,
            "arn:aws:ec2:us-east-1:"
            "123456789012:security-group/sg-123",
            {
                "IpPermissions": [
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 22,
                        "ToPort": 22,
                        "IpRanges": [
                            {
                                "CidrIp": (
                                    "0.0.0.0/0"
                                )
                            }
                        ],
                    }
                ]
            },
        )

        mock_ec2.authorize_security_group_ingress.assert_called_once()

    def test_sg_authorize_non_duplicate_raises(
        self,
    ):
        """Non-duplicate ClientError is re-raised."""
        from botocore.exceptions import ClientError

        mock_session = MagicMock()
        mock_ec2 = MagicMock()
        mock_session.client.return_value = mock_ec2

        mock_ec2.authorize_security_group_ingress.side_effect = (
            ClientError(
                {
                    "Error": {
                        "Code": "UnauthorizedAccess",
                        "Message": "Access denied",
                    }
                },
                "AuthorizeSecurityGroupIngress",
            )
        )

        import pytest

        with pytest.raises(ClientError):
            _rollback_security_group(
                mock_session,
                "arn:aws:ec2:us-east-1:"
                "123456789012:"
                "security-group/sg-123",
                {
                    "IpPermissions": [
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 22,
                            "ToPort": 22,
                            "IpRanges": [
                                {
                                    "CidrIp": (
                                        "0.0.0.0/0"
                                    )
                                }
                            ],
                        }
                    ]
                },
            )
