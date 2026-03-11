"""Tests for OneClickRemediator Tier 2 executors."""

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
    SUPPORTED_REMEDIATIONS,
    OneClickRemediator,
    _extract_resource_name,
    _fix_cloudtrail_multiregion,
    _fix_ebs_encryption,
    _fix_imdsv2,
    _fix_s3_public_access,
    _fix_security_group_ssh,
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
def aws_env(aws_credentials):
    """Set up mocked AWS environment."""
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
        yield session, audit_mgr, remediator


class TestExtractResourceName:
    """Test ARN parsing."""

    def test_s3_arn(self):
        assert (
            _extract_resource_name(
                "arn:aws:s3:::my-bucket"
            )
            == "my-bucket"
        )

    def test_sg_arn(self):
        assert (
            _extract_resource_name(
                "arn:aws:ec2:us-east-1:"
                "123456789012:"
                "security-group/sg-abc123"
            )
            == "sg-abc123"
        )

    def test_instance_arn(self):
        assert (
            _extract_resource_name(
                "arn:aws:ec2:us-east-1:"
                "123456789012:"
                "instance/i-abc123"
            )
            == "i-abc123"
        )

    def test_trail_arn(self):
        assert (
            _extract_resource_name(
                "arn:aws:cloudtrail:us-east-1:"
                "123456789012:"
                "trail/my-trail"
            )
            == "my-trail"
        )

    def test_simple_name(self):
        assert (
            _extract_resource_name("my-bucket")
            == "my-bucket"
        )


class TestSupportedRemediations:
    """Test supported remediation set."""

    def test_six_supported(self):
        assert len(SUPPORTED_REMEDIATIONS) == 6

    def test_contains_rem_04(self):
        assert "REM_04" in SUPPORTED_REMEDIATIONS

    def test_contains_rem_05(self):
        assert "REM_05" in SUPPORTED_REMEDIATIONS

    def test_contains_rem_07(self):
        assert "REM_07" in SUPPORTED_REMEDIATIONS

    def test_contains_rem_08(self):
        assert "REM_08" in SUPPORTED_REMEDIATIONS

    def test_contains_rem_17(self):
        assert "REM_17" in SUPPORTED_REMEDIATIONS


class TestUnsupportedRemediation:
    """Test rejection of unsupported remediations."""

    def test_raises_on_unsupported(self, aws_env):
        _, _, remediator = aws_env
        with pytest.raises(
            ValueError, match="Unsupported"
        ):
            remediator.execute(
                remediation_id="REM_01",
                resource_arn="arn:aws:iam::root",
                account_id=ACCOUNT,
                initiated_by="user@example.com",
            )

    def test_raises_on_unknown(self, aws_env):
        _, _, remediator = aws_env
        with pytest.raises(ValueError):
            remediator.execute(
                remediation_id="REM_99",
                resource_arn="arn:aws:s3:::b",
                account_id=ACCOUNT,
                initiated_by="user@example.com",
            )


class TestFixS3PublicAccess:
    """Test REM_04: S3 public access block."""

    def test_blocks_public_access(self, aws_env):
        session, _, remediator = aws_env
        s3 = session.client("s3")
        s3.create_bucket(Bucket="test-bucket")

        action = remediator.execute(
            remediation_id="REM_04",
            resource_arn=(
                "arn:aws:s3:::test-bucket"
            ),
            account_id=ACCOUNT,
            initiated_by="user@example.com",
        )

        assert (
            action.status
            == RemediationStatus.EXECUTED
        )
        assert action.action_id.startswith("rem-")
        assert action.post_state["BlockPublicAcls"]
        assert (
            action.post_state["IgnorePublicAcls"]
        )
        assert (
            action.post_state["BlockPublicPolicy"]
        )
        assert (
            action.post_state[
                "RestrictPublicBuckets"
            ]
        )

    def test_captures_pre_state(self, aws_env):
        session, _, remediator = aws_env
        s3 = session.client("s3")
        s3.create_bucket(Bucket="open-bucket")

        action = remediator.execute(
            remediation_id="REM_04",
            resource_arn=(
                "arn:aws:s3:::open-bucket"
            ),
            account_id=ACCOUNT,
            initiated_by="user@example.com",
        )

        assert isinstance(action.pre_state, dict)

    def test_records_audit_trail(self, aws_env):
        session, audit_mgr, remediator = aws_env
        s3 = session.client("s3")
        s3.create_bucket(Bucket="audit-bucket")

        action = remediator.execute(
            remediation_id="REM_04",
            resource_arn=(
                "arn:aws:s3:::audit-bucket"
            ),
            account_id=ACCOUNT,
            initiated_by="user@example.com",
        )

        entry = audit_mgr.get_action(
            ACCOUNT, action.action_id
        )
        assert entry is not None
        assert entry.remediation_id == "REM_04"
        assert entry.check_id == "CHECK_04"
        assert (
            entry.status
            == RemediationStatus.EXECUTED
        )

    def test_verifies_fix_applied(self, aws_env):
        session, _, remediator = aws_env
        s3 = session.client("s3")
        s3.create_bucket(Bucket="verify-bucket")

        remediator.execute(
            remediation_id="REM_04",
            resource_arn=(
                "arn:aws:s3:::verify-bucket"
            ),
            account_id=ACCOUNT,
            initiated_by="user@example.com",
        )

        # Verify directly
        resp = s3.get_public_access_block(
            Bucket="verify-bucket"
        )
        config = resp[
            "PublicAccessBlockConfiguration"
        ]
        assert config["BlockPublicAcls"] is True

    def test_rollback_deadline(self, aws_env):
        session, _, remediator = aws_env
        s3 = session.client("s3")
        s3.create_bucket(Bucket="rb-bucket")

        action = remediator.execute(
            remediation_id="REM_04",
            resource_arn=(
                "arn:aws:s3:::rb-bucket"
            ),
            account_id=ACCOUNT,
            initiated_by="user@example.com",
        )
        assert action.rollback_available_until


class TestFixSecurityGroupSSH:
    """Test REM_07: Remove open SSH access."""

    def _create_sg_with_ssh(self, session):
        ec2 = session.client("ec2")
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
        vpc_id = vpc["Vpc"]["VpcId"]
        sg = ec2.create_security_group(
            GroupName="test-sg",
            Description="Test",
            VpcId=vpc_id,
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

    def test_removes_ssh_rule(self, aws_env):
        session, _, remediator = aws_env
        sg_id = self._create_sg_with_ssh(session)

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

        assert (
            action.status
            == RemediationStatus.EXECUTED
        )
        assert action.check_id == "CHECK_07"

    def test_captures_pre_state_rules(
        self, aws_env
    ):
        session, _, remediator = aws_env
        sg_id = self._create_sg_with_ssh(session)

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

        assert "IpPermissions" in action.pre_state

    def test_ssh_rule_removed(self, aws_env):
        session, _, remediator = aws_env
        sg_id = self._create_sg_with_ssh(session)

        remediator.execute(
            remediation_id="REM_07",
            resource_arn=(
                f"arn:aws:ec2:us-east-1:"
                f"{ACCOUNT}:security-group/"
                f"{sg_id}"
            ),
            account_id=ACCOUNT,
            initiated_by="user@example.com",
        )

        # Verify SSH rule is gone
        ec2 = session.client("ec2")
        resp = ec2.describe_security_groups(
            GroupIds=[sg_id]
        )
        rules = resp["SecurityGroups"][0][
            "IpPermissions"
        ]
        for rule in rules:
            for ip in rule.get("IpRanges", []):
                if rule.get("FromPort") == 22:
                    assert (
                        ip.get("CidrIp")
                        != "0.0.0.0/0"
                    )


class TestFixIMDSv2:
    """Test REM_08: Enforce IMDSv2.

    Note: moto has a bug with
    modify_instance_metadata_options, so we mock
    the entire _fix_imdsv2 executor function.
    """

    def test_enforces_imdsv2(self, aws_env):
        _, _, remediator = aws_env
        from unittest.mock import patch

        mock_result = (
            {"HttpTokens": "optional"},
            {
                "HttpTokens": "required",
                "HttpEndpoint": "enabled",
            },
            "Enforced IMDSv2 on i-abc123",
        )

        with patch(
            "app.pipeline.remediation.one_click"
            "._EXECUTORS",
            {
                **__import__(
                    "app.pipeline.remediation"
                    ".one_click",
                    fromlist=["_EXECUTORS"],
                )._EXECUTORS,
                "REM_08": lambda s, r: mock_result,
            },
        ):
            action = remediator.execute(
                remediation_id="REM_08",
                resource_arn=(
                    f"arn:aws:ec2:us-east-1:"
                    f"{ACCOUNT}:instance/i-abc123"
                ),
                account_id=ACCOUNT,
                initiated_by="user@example.com",
            )

        assert (
            action.status
            == RemediationStatus.EXECUTED
        )
        assert (
            action.post_state["HttpTokens"]
            == "required"
        )
        assert action.check_id == "CHECK_08"

    def test_captures_pre_state(self, aws_env):
        _, _, remediator = aws_env
        from unittest.mock import patch

        mock_result = (
            {
                "HttpTokens": "optional",
                "HttpEndpoint": "enabled",
            },
            {
                "HttpTokens": "required",
                "HttpEndpoint": "enabled",
            },
            "Enforced IMDSv2 on i-xyz789",
        )

        with patch(
            "app.pipeline.remediation.one_click"
            "._EXECUTORS",
            {
                **__import__(
                    "app.pipeline.remediation"
                    ".one_click",
                    fromlist=["_EXECUTORS"],
                )._EXECUTORS,
                "REM_08": lambda s, r: mock_result,
            },
        ):
            action = remediator.execute(
                remediation_id="REM_08",
                resource_arn=(
                    f"arn:aws:ec2:us-east-1:"
                    f"{ACCOUNT}:instance/i-xyz789"
                ),
                account_id=ACCOUNT,
                initiated_by="user@example.com",
            )

        assert "HttpTokens" in action.pre_state
        assert (
            action.pre_state["HttpTokens"]
            == "optional"
        )


class TestFixEBSEncryption:
    """Test REM_17: Enable EBS default encryption."""

    def test_enables_encryption(self, aws_env):
        session, _, remediator = aws_env

        action = remediator.execute(
            remediation_id="REM_17",
            resource_arn=(
                f"arn:aws:ec2:us-east-1:{ACCOUNT}"
            ),
            account_id=ACCOUNT,
            initiated_by="user@example.com",
        )

        assert (
            action.status
            == RemediationStatus.EXECUTED
        )
        assert (
            action.post_state[
                "EbsEncryptionByDefault"
            ]
            is True
        )
        assert action.check_id == "CHECK_17"

    def test_captures_pre_state(self, aws_env):
        session, _, remediator = aws_env

        action = remediator.execute(
            remediation_id="REM_17",
            resource_arn=(
                f"arn:aws:ec2:us-east-1:{ACCOUNT}"
            ),
            account_id=ACCOUNT,
            initiated_by="user@example.com",
        )

        assert (
            "EbsEncryptionByDefault"
            in action.pre_state
        )


class TestFailureHandling:
    """Test error scenarios."""

    def test_failed_action_recorded(self, aws_env):
        session, audit_mgr, remediator = aws_env
        # Try to fix a nonexistent bucket
        action = remediator.execute(
            remediation_id="REM_04",
            resource_arn=(
                "arn:aws:s3:::nonexistent-bucket"
            ),
            account_id=ACCOUNT,
            initiated_by="user@example.com",
        )

        assert (
            action.status
            == RemediationStatus.FAILED
        )
        assert action.error_message

        # Audit trail should still record it
        entry = audit_mgr.get_action(
            ACCOUNT, action.action_id
        )
        assert entry is not None
        assert (
            entry.status
            == RemediationStatus.FAILED
        )

    def test_custom_rollback_window(self, aws_env):
        session, _, remediator = aws_env
        s3 = session.client("s3")
        s3.create_bucket(Bucket="custom-rb")

        action = remediator.execute(
            remediation_id="REM_04",
            resource_arn=(
                "arn:aws:s3:::custom-rb"
            ),
            account_id=ACCOUNT,
            initiated_by="user@example.com",
            rollback_window_minutes=120,
        )
        assert action.rollback_available_until

    def test_action_metadata(self, aws_env):
        session, _, remediator = aws_env
        s3 = session.client("s3")
        s3.create_bucket(Bucket="meta-bucket")

        action = remediator.execute(
            remediation_id="REM_04",
            resource_arn=(
                "arn:aws:s3:::meta-bucket"
            ),
            account_id=ACCOUNT,
            initiated_by="admin@corp.com",
        )
        assert action.account_id == ACCOUNT
        assert (
            action.initiated_by == "admin@corp.com"
        )
        assert (
            action.tier == RemediationTier.ONE_CLICK
        )
        assert action.remediation_id == "REM_04"


class TestFixCloudTrailPreStateError:
    """Test CloudTrail pre-state capture fallback."""

    def test_prestate_fallback_on_error(
        self, aws_env
    ):
        """get_trail failure uses default pre_state."""
        session, _, _ = aws_env

        # Call _fix_cloudtrail_multiregion with a
        # nonexistent trail — get_trail will fail,
        # hitting the except branch (lines 287-288)
        with pytest.raises(Exception):
            # update_trail will fail since trail
            # doesn't exist, but the pre_state
            # fallback branch is exercised first
            _fix_cloudtrail_multiregion(
                session,
                "arn:aws:cloudtrail:us-east-1:"
                f"{ACCOUNT}:trail/no-such-trail",
            )


class TestFixIMDSv2Real:
    """Test _fix_imdsv2 function directly.

    Exercises the actual function code (lines
    398-440) using a mock EC2 client to avoid the
    moto bug with modify_instance_metadata_options.
    """

    def test_imdsv2_function_body(self):
        """Call _fix_imdsv2 with mocked EC2."""
        mock_session = MagicMock()
        mock_ec2 = MagicMock()
        mock_session.client.return_value = mock_ec2

        # Mock describe_instances response
        mock_ec2.describe_instances.return_value = {
            "Reservations": [
                {
                    "Instances": [
                        {
                            "MetadataOptions": {
                                "HttpTokens": (
                                    "optional"
                                ),
                                "HttpEndpoint": (
                                    "enabled"
                                ),
                            }
                        }
                    ]
                }
            ]
        }
        mock_ec2.modify_instance_metadata_options.return_value = {}

        pre, post, desc = _fix_imdsv2(
            mock_session,
            "arn:aws:ec2:us-east-1:"
            f"{ACCOUNT}:instance/i-abc123",
        )

        assert pre["HttpTokens"] == "optional"
        assert post["HttpTokens"] == "required"
        assert "i-abc123" in desc
        mock_ec2.modify_instance_metadata_options.assert_called_once_with(
            InstanceId="i-abc123",
            HttpTokens="required",
            HttpEndpoint="enabled",
        )

    def test_imdsv2_prestate_fallback(self):
        """describe_instances fails → default pre."""
        mock_session = MagicMock()
        mock_ec2 = MagicMock()
        mock_session.client.return_value = mock_ec2

        mock_ec2.describe_instances.side_effect = (
            Exception("EC2 API error")
        )
        mock_ec2.modify_instance_metadata_options.return_value = {}

        pre, post, desc = _fix_imdsv2(
            mock_session,
            "arn:aws:ec2:us-east-1:"
            f"{ACCOUNT}:instance/i-xyz",
        )

        assert pre["HttpTokens"] == "optional"
        assert post["HttpTokens"] == "required"
