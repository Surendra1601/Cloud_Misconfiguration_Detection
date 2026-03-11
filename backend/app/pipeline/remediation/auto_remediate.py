"""Tier 3 automatic remediation engine.

Orchestrates automatic remediation when violations
are detected, based on per-check/per-account config.
Checks eligibility, executes fix via OneClickRemediator,
sends SNS notification, and logs audit trail.
"""

import logging

import boto3

from app.pipeline.remediation.config_manager import (
    ConfigManager,
)
from app.pipeline.remediation.models import (
    RemediationAction,
    RemediationStatus,
    RemediationTier,
)
from app.pipeline.remediation.one_click import (
    SUPPORTED_REMEDIATIONS,
    OneClickRemediator,
)

logger = logging.getLogger(__name__)


class AutoRemediationEngine:
    """Tier 3 auto-remediation orchestrator.

    When a violation is detected, checks if auto-
    remediation is enabled for that check+account,
    executes the fix, and sends SNS notification.

    Attributes:
        one_click: OneClickRemediator for execution.
        config_manager: Config lookup.
        sns_topic_arn: SNS topic for notifications.
        session: boto3 session for SNS.

    Example:
        >>> engine = AutoRemediationEngine(
        ...     one_click=remediator,
        ...     config_manager=config_mgr,
        ...     session=boto3.Session(),
        ... )
    """

    def __init__(
        self,
        one_click: OneClickRemediator,
        config_manager: ConfigManager,
        session: boto3.Session,
        sns_topic_arn: str = "",
    ) -> None:
        """Initialize AutoRemediationEngine.

        Args:
            one_click: For executing fixes.
            config_manager: For config lookups.
            session: boto3 session for SNS.
            sns_topic_arn: SNS topic ARN.
        """
        self.one_click = one_click
        self.config_manager = config_manager
        self.session = session
        self.sns_topic_arn = sns_topic_arn

    def evaluate_and_remediate(
        self,
        check_id: str,
        remediation_id: str,
        resource_arn: str,
        account_id: str,
        severity: str = "",
    ) -> RemediationAction | None:
        """Check config and auto-remediate if enabled.

        Args:
            check_id: Policy check ID.
            remediation_id: Template ID (REM_XX).
            resource_arn: Target AWS resource ARN.
            account_id: AWS account ID.
            severity: Violation severity level.

        Returns:
            RemediationAction if remediated,
            None if not eligible or not enabled.
        """
        # 1. Check if remediation is supported
        if (
            remediation_id
            not in SUPPORTED_REMEDIATIONS
        ):
            logger.debug(
                "Auto-remediation not supported "
                "for %s",
                remediation_id,
            )
            return None

        # 2. Check if auto-remediation is enabled
        config = self.config_manager.get_config(
            account_id, check_id
        )
        if config is None or not config.enabled:
            logger.debug(
                "Auto-remediation not enabled "
                "for %s/%s",
                account_id,
                check_id,
            )
            return None

        # 3. Execute remediation
        logger.info(
            "Auto-remediating %s for %s on %s",
            check_id,
            account_id,
            resource_arn,
        )

        action = self.one_click.execute(
            remediation_id=remediation_id,
            resource_arn=resource_arn,
            account_id=account_id,
            initiated_by="SYSTEM",
            rollback_window_minutes=(
                config.rollback_window_minutes
            ),
        )

        # 4. Override tier to AUTO
        action.tier = RemediationTier.AUTO

        # 5. Send SNS notification
        if (
            config.notify_on_action
            and self.sns_topic_arn
        ):
            self._send_notification(
                action, check_id, severity
            )

        return action

    def _send_notification(
        self,
        action: RemediationAction,
        check_id: str,
        severity: str,
    ) -> None:
        """Send SNS notification for auto-remediation.

        Args:
            action: Completed remediation action.
            check_id: Policy check ID.
            severity: Violation severity.
        """
        try:
            sns = self.session.client("sns")
            status = action.status.value
            subject = (
                f"Auto-Remediation: {check_id} "
                f"[{status}]"
            )
            message = (
                f"Auto-Remediation Report\n"
                f"=======================\n"
                f"Check: {check_id}\n"
                f"Remediation: "
                f"{action.remediation_id}\n"
                f"Resource: {action.resource_arn}\n"
                f"Account: {action.account_id}\n"
                f"Severity: {severity}\n"
                f"Status: {status}\n"
                f"Action ID: {action.action_id}\n"
                f"Rollback until: "
                f"{action.rollback_available_until}"
            )
            sns.publish(
                TopicArn=self.sns_topic_arn,
                Subject=subject[:100],
                Message=message,
            )
            logger.info(
                "SNS notification sent for %s",
                action.action_id,
            )
        except Exception as e:
            logger.error(
                "SNS notification failed: %s", e
            )

    def is_eligible(
        self,
        check_id: str,
        remediation_id: str,
        account_id: str,
    ) -> bool:
        """Check if a violation is eligible for auto.

        Args:
            check_id: Policy check ID.
            remediation_id: Template ID.
            account_id: AWS account ID.

        Returns:
            True if eligible for auto-remediation.
        """
        if (
            remediation_id
            not in SUPPORTED_REMEDIATIONS
        ):
            return False
        return self.config_manager.is_enabled(
            account_id, check_id
        )
