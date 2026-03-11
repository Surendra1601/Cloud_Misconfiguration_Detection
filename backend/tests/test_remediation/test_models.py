"""Tests for remediation data models."""

from datetime import datetime

from app.pipeline.remediation.models import (
    AutoRemediationConfig,
    ComplianceReference,
    RemediationAction,
    RemediationAuditEntry,
    RemediationStatus,
    RemediationTemplate,
    RemediationTier,
)


class TestRemediationTier:
    """Test tier enum values."""

    def test_suggestion(self):
        assert (
            RemediationTier.SUGGESTION
            == "tier_1_suggestion"
        )

    def test_one_click(self):
        assert (
            RemediationTier.ONE_CLICK
            == "tier_2_oneclick"
        )

    def test_auto(self):
        assert RemediationTier.AUTO == "tier_3_auto"

    def test_from_string(self):
        t = RemediationTier("tier_1_suggestion")
        assert t == RemediationTier.SUGGESTION


class TestRemediationStatus:
    """Test status enum values."""

    def test_pending(self):
        assert (
            RemediationStatus.PENDING == "pending"
        )

    def test_executed(self):
        assert (
            RemediationStatus.EXECUTED == "executed"
        )

    def test_failed(self):
        assert RemediationStatus.FAILED == "failed"

    def test_rolled_back(self):
        assert (
            RemediationStatus.ROLLED_BACK
            == "rolled_back"
        )


class TestComplianceReference:
    """Test compliance reference model."""

    def test_create(self):
        ref = ComplianceReference(
            framework="CIS AWS",
            control_id="1.5",
            title="MFA check",
        )
        assert ref.framework == "CIS AWS"
        assert ref.control_id == "1.5"
        assert ref.title == "MFA check"

    def test_default_title(self):
        ref = ComplianceReference(
            framework="NIST",
            control_id="IA-2",
        )
        assert ref.title == ""


class TestRemediationTemplate:
    """Test remediation template model."""

    def test_create_minimal(self):
        t = RemediationTemplate(
            remediation_id="REM_01",
            title="Enable Root MFA",
        )
        assert t.remediation_id == "REM_01"
        assert t.title == "Enable Root MFA"
        assert t.domain == ""
        assert t.console_steps == []
        assert t.references == []
        assert t.estimated_fix_time_minutes == 5

    def test_create_full(self):
        t = RemediationTemplate(
            remediation_id="REM_04",
            title="S3 Public Access Block",
            domain="data_protection",
            severity="critical",
            check_id="CHECK_04",
            console_steps=[
                "Step 1",
                "Step 2",
            ],
            cli_command="aws s3api ...",
            cli_example="aws s3api put...",
            terraform_snippet='resource "aws"{}',
            references=[
                ComplianceReference(
                    framework="CIS",
                    control_id="2.1.4",
                )
            ],
            estimated_fix_time_minutes=10,
            risk_reduction="Critical",
            rollback_difficulty="Easy",
        )
        assert t.domain == "data_protection"
        assert t.severity == "critical"
        assert len(t.console_steps) == 2
        assert len(t.references) == 1
        assert t.estimated_fix_time_minutes == 10

    def test_serialization(self):
        t = RemediationTemplate(
            remediation_id="REM_07",
            title="Remove SSH",
        )
        data = t.model_dump()
        assert data["remediation_id"] == "REM_07"
        assert isinstance(data["console_steps"], list)


class TestRemediationAction:
    """Test remediation action model."""

    def test_create(self):
        a = RemediationAction(
            action_id="rem-001",
            remediation_id="REM_04",
            resource_arn="arn:aws:s3:::bucket",
            account_id="123456789012",
            tier=RemediationTier.ONE_CLICK,
            status=RemediationStatus.EXECUTED,
            initiated_by="user@example.com",
        )
        assert a.action_id == "rem-001"
        assert a.tier == RemediationTier.ONE_CLICK
        assert a.status == RemediationStatus.EXECUTED
        assert a.pre_state == {}
        assert a.post_state == {}
        assert a.error_message == ""

    def test_defaults(self):
        a = RemediationAction(
            action_id="rem-002",
            remediation_id="REM_07",
            resource_arn="arn:aws:ec2:::sg",
        )
        assert a.tier == RemediationTier.ONE_CLICK
        assert a.status == RemediationStatus.PENDING
        assert a.account_id == ""
        assert a.created_at  # auto-generated

    def test_created_at_auto(self):
        a = RemediationAction(
            action_id="rem-003",
            remediation_id="REM_04",
            resource_arn="arn:aws:s3:::b",
        )
        assert a.created_at  # auto-generated
        # Should be parseable as ISO
        dt = datetime.fromisoformat(a.created_at)
        assert isinstance(dt, datetime)

    def test_with_state(self):
        a = RemediationAction(
            action_id="rem-004",
            remediation_id="REM_04",
            resource_arn="arn:aws:s3:::b",
            pre_state={"public": True},
            post_state={"public": False},
        )
        assert a.pre_state["public"] is True
        assert a.post_state["public"] is False

    def test_failed_action(self):
        a = RemediationAction(
            action_id="rem-005",
            remediation_id="REM_04",
            resource_arn="arn:aws:s3:::b",
            status=RemediationStatus.FAILED,
            error_message="Access denied",
        )
        assert a.status == RemediationStatus.FAILED
        assert "Access denied" in a.error_message


class TestRemediationAuditEntry:
    """Test audit entry model."""

    def test_create(self):
        e = RemediationAuditEntry(
            action_id="rem-001",
            account_id="123456789012",
            remediation_id="REM_04",
            check_id="CHECK_04",
            resource_arn="arn:aws:s3:::bucket",
            action_taken="Blocked public access",
            tier=RemediationTier.ONE_CLICK,
            initiated_by="user@example.com",
            status=RemediationStatus.EXECUTED,
        )
        assert e.action_id == "rem-001"
        assert e.account_id == "123456789012"
        assert e.tier == RemediationTier.ONE_CLICK
        assert e.created_at  # auto-generated

    def test_defaults(self):
        e = RemediationAuditEntry(
            action_id="rem-002",
            account_id="123456789012",
            remediation_id="REM_07",
        )
        assert e.check_id == ""
        assert e.resource_arn == ""
        assert e.pre_state == {}
        assert e.post_state == {}
        assert e.rollback_deadline == ""

    def test_with_rollback(self):
        e = RemediationAuditEntry(
            action_id="rem-003",
            account_id="123456789012",
            remediation_id="REM_04",
            rollback_deadline=(
                "2026-03-01T14:00:00Z"
            ),
            pre_state={"BlockPublicAcls": False},
            post_state={"BlockPublicAcls": True},
        )
        assert e.rollback_deadline.endswith("Z")
        assert e.pre_state["BlockPublicAcls"] is False

    def test_serialization_roundtrip(self):
        e = RemediationAuditEntry(
            action_id="rem-004",
            account_id="123456789012",
            remediation_id="REM_04",
            tier=RemediationTier.AUTO,
            initiated_by="SYSTEM",
            approved_by="auto-policy",
        )
        data = e.model_dump()
        restored = RemediationAuditEntry(**data)
        assert restored.tier == RemediationTier.AUTO
        assert restored.initiated_by == "SYSTEM"


class TestAutoRemediationConfig:
    """Test auto-remediation config model."""

    def test_create(self):
        cfg = AutoRemediationConfig(
            account_id="123456789012",
            check_id="CHECK_04",
            enabled=True,
            approved_by="admin@example.com",
        )
        assert cfg.account_id == "123456789012"
        assert cfg.check_id == "CHECK_04"
        assert cfg.enabled is True
        assert cfg.rollback_window_minutes == 60
        assert cfg.notify_on_action is True

    def test_defaults(self):
        cfg = AutoRemediationConfig(
            account_id="123456789012",
            check_id="CHECK_07",
        )
        assert cfg.enabled is False
        assert cfg.rollback_window_minutes == 60
        assert cfg.notify_on_action is True
        assert cfg.approved_by == ""
        assert cfg.approved_at == ""

    def test_custom_rollback_window(self):
        cfg = AutoRemediationConfig(
            account_id="123456789012",
            check_id="CHECK_04",
            rollback_window_minutes=120,
        )
        assert cfg.rollback_window_minutes == 120

    def test_disabled(self):
        cfg = AutoRemediationConfig(
            account_id="123456789012",
            check_id="CHECK_04",
            enabled=False,
        )
        assert cfg.enabled is False
