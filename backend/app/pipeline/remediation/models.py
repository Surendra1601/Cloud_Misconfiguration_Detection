"""Data models for the automated remediation engine.

Defines templates, actions, audit entries, and
auto-remediation configuration structures.
"""

from datetime import UTC, datetime
from enum import Enum

from pydantic import BaseModel, Field


class RemediationTier(str, Enum):
    """Remediation tier levels."""

    SUGGESTION = "tier_1_suggestion"
    ONE_CLICK = "tier_2_oneclick"
    AUTO = "tier_3_auto"


class RemediationStatus(str, Enum):
    """Status of a remediation action."""

    PENDING = "pending"
    EXECUTED = "executed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


class ComplianceReference(BaseModel):
    """Compliance framework reference for a template.

    Attributes:
        framework: Name of the compliance framework.
        control_id: Control identifier within framework.
        title: Human-readable control title.

    Example:
        >>> ref = ComplianceReference(
        ...     framework="CIS AWS Foundations",
        ...     control_id="1.5",
        ...     title="Ensure MFA is enabled",
        ... )
    """

    framework: str
    control_id: str
    title: str = ""


class RemediationTemplate(BaseModel):
    """Tier 1 remediation suggestion template.

    Attributes:
        remediation_id: Unique template ID (REM_XX).
        title: Human-readable fix title.
        domain: Security domain.
        severity: Severity level of the check.
        check_id: Linked policy check ID.
        console_steps: Step-by-step AWS Console fix.
        cli_command: AWS CLI command template.
        cli_example: CLI command with example values.
        terraform_snippet: Terraform HCL fix code.
        references: Compliance framework references.
        estimated_fix_time_minutes: Time estimate.
        risk_reduction: Impact description.
        rollback_difficulty: Rollback complexity.

    Example:
        >>> t = RemediationTemplate(
        ...     remediation_id="REM_04",
        ...     title="Enable S3 Public Access Block",
        ...     domain="data_protection",
        ...     severity="critical",
        ...     check_id="CHECK_04",
        ...     console_steps=["Open S3 console"],
        ...     cli_command="aws s3api ...",
        ... )
    """

    remediation_id: str
    title: str
    domain: str = ""
    severity: str = ""
    check_id: str = ""
    console_steps: list[str] = Field(
        default_factory=list
    )
    cli_command: str = ""
    cli_example: str = ""
    terraform_snippet: str = ""
    references: list[ComplianceReference] = Field(
        default_factory=list
    )
    estimated_fix_time_minutes: int = 5
    risk_reduction: str = ""
    rollback_difficulty: str = ""


class RemediationAction(BaseModel):
    """Result of executing a remediation action.

    Attributes:
        action_id: Unique action identifier.
        remediation_id: Template ID used.
        resource_arn: Target AWS resource ARN.
        account_id: AWS account ID.
        tier: Which tier executed this action.
        status: Current action status.
        initiated_by: User email or SYSTEM.
        approved_by: Approver email or policy name.
        pre_state: Resource config before fix.
        post_state: Resource config after fix.
        rollback_available_until: ISO timestamp.
        error_message: Error details if failed.
        created_at: When the action was created.

    Example:
        >>> a = RemediationAction(
        ...     action_id="rem-20260301-001",
        ...     remediation_id="REM_04",
        ...     resource_arn="arn:aws:s3:::bucket",
        ...     account_id="123456789012",
        ...     tier=RemediationTier.ONE_CLICK,
        ...     status=RemediationStatus.EXECUTED,
        ...     initiated_by="user@example.com",
        ... )
    """

    action_id: str
    remediation_id: str
    resource_arn: str
    account_id: str = ""
    tier: RemediationTier = RemediationTier.ONE_CLICK
    status: RemediationStatus = (
        RemediationStatus.PENDING
    )
    initiated_by: str = ""
    approved_by: str = ""
    check_id: str = ""
    pre_state: dict = Field(default_factory=dict)
    post_state: dict = Field(default_factory=dict)
    rollback_available_until: str = ""
    error_message: str = ""
    created_at: str = Field(
        default_factory=lambda: (
            datetime.now(UTC).isoformat()
        )
    )


class RemediationAuditEntry(BaseModel):
    """DynamoDB audit trail record for remediation.

    Attributes:
        action_id: Unique action identifier.
        account_id: AWS account ID (partition key).
        remediation_id: Template ID used.
        check_id: Policy check that triggered this.
        resource_arn: Target resource ARN.
        action_taken: Description of the fix applied.
        tier: Which tier executed this.
        initiated_by: User email or SYSTEM.
        approved_by: Approver or policy name.
        status: Action outcome.
        rollback_deadline: ISO timestamp for rollback.
        pre_state: Config snapshot before fix.
        post_state: Config snapshot after fix.
        created_at: When the action was recorded.

    Example:
        >>> entry = RemediationAuditEntry(
        ...     action_id="rem-20260301-001",
        ...     account_id="123456789012",
        ...     remediation_id="REM_04",
        ...     check_id="CHECK_04",
        ...     resource_arn="arn:aws:s3:::bucket",
        ...     action_taken="Blocked public access",
        ...     tier=RemediationTier.ONE_CLICK,
        ...     initiated_by="user@example.com",
        ... )
    """

    action_id: str
    account_id: str
    remediation_id: str
    check_id: str = ""
    resource_arn: str = ""
    action_taken: str = ""
    tier: RemediationTier = RemediationTier.ONE_CLICK
    initiated_by: str = ""
    approved_by: str = ""
    status: RemediationStatus = (
        RemediationStatus.PENDING
    )
    rollback_deadline: str = ""
    pre_state: dict = Field(default_factory=dict)
    post_state: dict = Field(default_factory=dict)
    created_at: str = Field(
        default_factory=lambda: (
            datetime.now(UTC).isoformat()
        )
    )


class AutoRemediationConfig(BaseModel):
    """Per-check, per-account auto-remediation config.

    Attributes:
        account_id: AWS account ID.
        check_id: Policy check identifier.
        enabled: Whether auto-remediation is active.
        rollback_window_minutes: Rollback availability.
        notify_on_action: Send SNS on auto-fix.
        approved_by: Admin who enabled this.
        approved_at: When approval was granted.

    Example:
        >>> cfg = AutoRemediationConfig(
        ...     account_id="123456789012",
        ...     check_id="CHECK_04",
        ...     enabled=True,
        ...     approved_by="admin@example.com",
        ... )
    """

    account_id: str
    check_id: str
    enabled: bool = False
    rollback_window_minutes: int = 60
    notify_on_action: bool = True
    approved_by: str = ""
    approved_at: str = ""
