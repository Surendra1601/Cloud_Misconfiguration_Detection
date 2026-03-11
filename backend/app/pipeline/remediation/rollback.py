"""Rollback manager for remediation actions.

Restores pre-remediation state within the rollback
window. Uses pre_state snapshots from audit trail
to reverse boto3 changes.
"""

import logging
from collections.abc import Callable
from datetime import UTC, datetime

import boto3
from botocore.exceptions import ClientError

from app.pipeline.remediation.audit_manager import (
    AuditManager,
)
from app.pipeline.remediation.models import (
    RemediationStatus,
)

logger = logging.getLogger(__name__)


class RollbackManager:
    """Manages rollback of remediation actions.

    Looks up the pre-state from audit trail and
    restores it, then marks the action as rolled_back.

    Attributes:
        session: boto3 session for AWS API calls.
        audit_manager: Audit trail for lookups.

    Example:
        >>> mgr = RollbackManager(
        ...     session=boto3.Session(),
        ...     audit_manager=audit_mgr,
        ... )
    """

    def __init__(
        self,
        session: boto3.Session,
        audit_manager: AuditManager,
    ) -> None:
        """Initialize RollbackManager.

        Args:
            session: boto3 session.
            audit_manager: For audit lookups.
        """
        self.session = session
        self.audit_manager = audit_manager

    def rollback(
        self,
        action_id: str,
        account_id: str,
    ) -> dict:
        """Rollback a previous remediation action.

        Checks that the rollback window hasn't expired,
        restores pre_state config, and marks the action
        as rolled_back in the audit trail.

        Args:
            action_id: The action to roll back.
            account_id: AWS account ID.

        Returns:
            Dict with rollback result details.

        Example:
            >>> result = mgr.rollback(
            ...     "rem-20260301-abc", "123456789012"
            ... )
            >>> result["status"]
            'rolled_back'
        """
        # 1. Look up the action
        entry = self.audit_manager.get_action(
            account_id, action_id
        )
        if entry is None:
            return {
                "status": "error",
                "message": (
                    f"Action {action_id} not found"
                ),
            }

        # 2. Check if already rolled back
        if (
            entry.status
            == RemediationStatus.ROLLED_BACK
        ):
            return {
                "status": "error",
                "message": "Already rolled back",
            }

        # 3. Check rollback window
        if entry.rollback_deadline:
            deadline = datetime.fromisoformat(
                entry.rollback_deadline
            )
            now = datetime.now(UTC)
            if now > deadline:
                return {
                    "status": "error",
                    "message": (
                        "Rollback window expired"
                    ),
                }

        # 4. Execute rollback
        rem_id = entry.remediation_id
        if rem_id not in _ROLLBACK_HANDLERS:
            return {
                "status": "error",
                "message": (
                    f"No rollback handler for "
                    f"{rem_id}"
                ),
            }

        handler = _ROLLBACK_HANDLERS[rem_id]
        try:
            handler(
                self.session,
                entry.resource_arn,
                entry.pre_state,
            )
        except Exception as e:
            logger.error(
                "Rollback failed for %s: %s",
                action_id,
                e,
            )
            return {
                "status": "error",
                "message": f"Rollback failed: {e}",
            }

        # 5. Update audit trail
        # Find the sort key by querying
        all_actions = (
            self.audit_manager.list_actions(
                account_id
            )
        )
        sk = None
        for a in all_actions:
            if a.action_id == action_id:
                # Reconstruct sk from created_at
                sk = (
                    f"{a.created_at}"
                    f"#{a.remediation_id}"
                )
                break

        if sk:
            self.audit_manager.update_status(
                account_id,
                sk,
                RemediationStatus.ROLLED_BACK,
            )

        return {
            "status": "rolled_back",
            "action_id": action_id,
            "remediation_id": rem_id,
            "message": (
                f"Rolled back {rem_id} on "
                f"{entry.resource_arn}"
            ),
        }


def _rollback_s3_public_access(
    session: boto3.Session,
    resource_arn: str,
    pre_state: dict,
) -> None:
    """Restore S3 public access block to pre-state.

    Args:
        session: boto3 session.
        resource_arn: S3 bucket ARN.
        pre_state: Previous config snapshot.
    """
    from app.pipeline.remediation.one_click import (
        _extract_resource_name,
    )

    bucket = _extract_resource_name(resource_arn)
    s3 = session.client("s3")

    if pre_state:
        s3.put_public_access_block(
            Bucket=bucket,
            PublicAccessBlockConfiguration=pre_state,
        )
    else:
        s3.delete_public_access_block(
            Bucket=bucket
        )


def _rollback_cloudtrail(
    session: boto3.Session,
    resource_arn: str,
    pre_state: dict,
) -> None:
    """Restore CloudTrail to pre-state.

    Args:
        session: boto3 session.
        resource_arn: Trail ARN.
        pre_state: Previous config snapshot.
    """
    from app.pipeline.remediation.one_click import (
        _extract_resource_name,
    )

    trail_name = _extract_resource_name(
        resource_arn
    )
    ct = session.client("cloudtrail")
    ct.update_trail(
        Name=trail_name,
        IsMultiRegionTrail=pre_state.get(
            "IsMultiRegionTrail", False
        ),
    )


def _rollback_security_group(
    session: boto3.Session,
    resource_arn: str,
    pre_state: dict,
) -> None:
    """Restore security group rules to pre-state.

    Re-adds the SSH rules that were removed.

    Args:
        session: boto3 session.
        resource_arn: Security group ARN.
        pre_state: Previous IpPermissions snapshot.
    """
    from app.pipeline.remediation.one_click import (
        _extract_resource_name,
    )

    sg_id = _extract_resource_name(resource_arn)
    ec2 = session.client("ec2")

    pre_rules = pre_state.get(
        "IpPermissions", []
    )
    for rule in pre_rules:
        from_port = int(
            rule.get("FromPort", 0)
        )
        to_port = int(rule.get("ToPort", 0))
        protocol = rule.get("IpProtocol", "tcp")
        # Restore IPv4 rules
        for ip_range in rule.get(
            "IpRanges", []
        ):
            cidr = ip_range.get("CidrIp", "")
            try:
                ec2.authorize_security_group_ingress(
                    GroupId=sg_id,
                    IpPermissions=[
                        {
                            "IpProtocol": protocol,
                            "FromPort": from_port,
                            "ToPort": to_port,
                            "IpRanges": [
                                {"CidrIp": cidr}
                            ],
                        }
                    ],
                )
            except ClientError as e:
                if "Duplicate" in str(e):
                    logger.debug(
                        "Rule already exists: %s",
                        e,
                    )
                else:
                    raise
        # Restore IPv6 rules
        for ip_range in rule.get(
            "Ipv6Ranges", []
        ):
            cidr6 = ip_range.get(
                "CidrIpv6", ""
            )
            try:
                ec2.authorize_security_group_ingress(
                    GroupId=sg_id,
                    IpPermissions=[
                        {
                            "IpProtocol": protocol,
                            "FromPort": from_port,
                            "ToPort": to_port,
                            "Ipv6Ranges": [
                                {
                                    "CidrIpv6": (
                                        cidr6
                                    )
                                }
                            ],
                        }
                    ],
                )
            except ClientError as e:
                if "Duplicate" in str(e):
                    logger.debug(
                        "Rule already exists: %s",
                        e,
                    )
                else:
                    raise


def _rollback_imdsv2(
    session: boto3.Session,
    resource_arn: str,
    pre_state: dict,
) -> None:
    """Restore IMDS settings to pre-state.

    Args:
        session: boto3 session.
        resource_arn: EC2 instance ARN.
        pre_state: Previous metadata options.
    """
    from app.pipeline.remediation.one_click import (
        _extract_resource_name,
    )

    instance_id = _extract_resource_name(
        resource_arn
    )
    ec2 = session.client("ec2")
    ec2.modify_instance_metadata_options(
        InstanceId=instance_id,
        HttpTokens=pre_state.get(
            "HttpTokens", "optional"
        ),
        HttpEndpoint=pre_state.get(
            "HttpEndpoint", "enabled"
        ),
    )


def _rollback_ebs_encryption(
    session: boto3.Session,
    resource_arn: str,
    pre_state: dict,
) -> None:
    """Restore EBS encryption default to pre-state.

    Args:
        session: boto3 session.
        resource_arn: Account-level ARN.
        pre_state: Previous encryption setting.
    """
    ec2 = session.client("ec2")
    if not pre_state.get(
        "EbsEncryptionByDefault", False
    ):
        ec2.disable_ebs_encryption_by_default()


# Rollback handler registry
_ROLLBACK_HANDLERS: dict[str, Callable] = {
    "REM_04": _rollback_s3_public_access,
    "REM_05": _rollback_cloudtrail,
    "REM_07": _rollback_security_group,
    "REM_07b": _rollback_security_group,
    "REM_08": _rollback_imdsv2,
    "REM_17": _rollback_ebs_encryption,
}
