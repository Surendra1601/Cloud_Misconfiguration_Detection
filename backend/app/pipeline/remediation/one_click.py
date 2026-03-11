"""Tier 2 one-click remediation executors.

Pre-built boto3 fix functions for the most critical
checks: S3 public access (REM_04), CloudTrail
multi-region (REM_05), security group SSH (REM_07),
security group RDP (REM_07b), IMDSv2 (REM_08),
EBS encryption (REM_17).

Each executor captures pre/post state for rollback
and records an audit trail entry.
"""

import logging
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import boto3

from app.pipeline.remediation.audit_manager import (
    AuditManager,
)
from app.pipeline.remediation.models import (
    RemediationAction,
    RemediationStatus,
    RemediationTier,
)

logger = logging.getLogger(__name__)

# Remediation IDs that support one-click execution
SUPPORTED_REMEDIATIONS = {
    "REM_04",
    "REM_05",
    "REM_07",
    "REM_07b",
    "REM_08",
    "REM_17",
}

# Maps remediation_id to check_id
_REM_TO_CHECK = {
    "REM_04": "CHECK_04",
    "REM_05": "CHECK_05",
    "REM_07": "CHECK_07",
    "REM_07b": "CHECK_07",
    "REM_08": "CHECK_08",
    "REM_17": "CHECK_17",
}


def _extract_resource_name(
    resource_arn: str,
) -> str:
    """Extract the resource name from an ARN.

    Handles standard ARN formats:
      arn:aws:s3:::bucket-name
      arn:aws:ec2:region:acct:instance/i-xxx
      arn:aws:iam::acct:user/path/name

    Does NOT handle edge cases with embedded
    slashes in trail/resource names.

    Args:
        resource_arn: Full AWS ARN string.

    Returns:
        Resource name/ID portion of the ARN.

    Example:
        >>> _extract_resource_name(
        ...     "arn:aws:s3:::my-bucket"
        ... )
        'my-bucket'
    """
    if not resource_arn.startswith("arn:"):
        logger.warning(
            "Not a valid ARN: '%s'",
            resource_arn,
        )
        return resource_arn
    parts = resource_arn.split(":")
    name = parts[-1] if parts else resource_arn
    if "/" in name:
        name = name.split("/")[-1]
    return name


class OneClickRemediator:
    """Executes Tier 2 one-click remediation fixes.

    Supports 5 critical checks with boto3 executors
    that capture pre/post state and audit each action.

    Attributes:
        session: boto3 session for AWS API calls.
        audit_manager: Audit trail manager.
        rollback_window: Default rollback window.

    Example:
        >>> rem = OneClickRemediator(
        ...     session=boto3.Session(),
        ...     audit_manager=audit_mgr,
        ... )
    """

    def __init__(
        self,
        session: boto3.Session,
        audit_manager: AuditManager,
        rollback_window_minutes: int = 60,
    ) -> None:
        """Initialize OneClickRemediator.

        Args:
            session: boto3 session.
            audit_manager: For recording actions.
            rollback_window_minutes: Default window.
        """
        self.session = session
        self.audit_manager = audit_manager
        self.rollback_window = (
            rollback_window_minutes
        )

    def execute(
        self,
        remediation_id: str,
        resource_arn: str,
        account_id: str,
        initiated_by: str,
        rollback_window_minutes: int | None = None,
    ) -> RemediationAction:
        """Execute a one-click remediation.

        Args:
            remediation_id: Template ID (REM_XX).
            resource_arn: Target AWS resource ARN.
            account_id: AWS account ID.
            initiated_by: User email or SYSTEM.
            rollback_window_minutes: Override default.

        Returns:
            RemediationAction with execution result.

        Raises:
            ValueError: If remediation_id not supported.
        """
        if (
            remediation_id
            not in SUPPORTED_REMEDIATIONS
        ):
            raise ValueError(
                f"Unsupported remediation: "
                f"{remediation_id}. Supported: "
                f"{SUPPORTED_REMEDIATIONS}"
            )

        window = (
            rollback_window_minutes
            or self.rollback_window
        )
        executor = _EXECUTORS[remediation_id]

        try:
            pre_state, post_state, action_desc = (
                executor(self.session, resource_arn)
            )
            status = RemediationStatus.EXECUTED
            error_msg = ""
        except Exception as e:
            logger.error(
                "Remediation %s failed for %s: %s",
                remediation_id,
                resource_arn,
                e,
            )
            pre_state = {}
            post_state = {}
            action_desc = f"Failed: {e}"
            status = RemediationStatus.FAILED
            error_msg = str(e)

        # Record audit trail
        action_id = self.audit_manager.record_action(
            account_id=account_id,
            remediation_id=remediation_id,
            check_id=_REM_TO_CHECK.get(
                remediation_id, ""
            ),
            resource_arn=resource_arn,
            action_taken=action_desc,
            tier=RemediationTier.ONE_CLICK,
            initiated_by=initiated_by,
            approved_by=initiated_by,
            status=status,
            pre_state=pre_state,
            post_state=post_state,
            rollback_window_minutes=window,
        )

        now = datetime.now(UTC)
        rollback_until = (
            now + timedelta(minutes=window)
        ).isoformat()

        return RemediationAction(
            action_id=action_id,
            remediation_id=remediation_id,
            resource_arn=resource_arn,
            account_id=account_id,
            tier=RemediationTier.ONE_CLICK,
            status=status,
            initiated_by=initiated_by,
            approved_by=initiated_by,
            check_id=_REM_TO_CHECK.get(
                remediation_id, ""
            ),
            pre_state=pre_state,
            post_state=post_state,
            rollback_available_until=rollback_until,
            error_message=error_msg,
        )


def _fix_s3_public_access(
    session: boto3.Session,
    resource_arn: str,
) -> tuple[dict, dict, str]:
    """REM_04: Block all S3 public access.

    Args:
        session: boto3 session.
        resource_arn: S3 bucket ARN.

    Returns:
        Tuple of (pre_state, post_state, description).
    """
    bucket = _extract_resource_name(resource_arn)
    s3 = session.client("s3")

    # Capture pre-state
    try:
        resp = s3.get_public_access_block(
            Bucket=bucket
        )
        pre_state = resp.get(
            "PublicAccessBlockConfiguration", {}
        )
    except Exception:
        pre_state = {
            "BlockPublicAcls": False,
            "IgnorePublicAcls": False,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": False,
        }

    # Apply fix
    config = {
        "BlockPublicAcls": True,
        "IgnorePublicAcls": True,
        "BlockPublicPolicy": True,
        "RestrictPublicBuckets": True,
    }
    s3.put_public_access_block(
        Bucket=bucket,
        PublicAccessBlockConfiguration=config,
    )

    return (
        pre_state,
        config,
        f"Blocked all public access on {bucket}",
    )


def _fix_cloudtrail_multiregion(
    session: boto3.Session,
    resource_arn: str,
) -> tuple[dict, dict, str]:
    """REM_05: Enable CloudTrail multi-region.

    Args:
        session: boto3 session.
        resource_arn: CloudTrail trail ARN.

    Returns:
        Tuple of (pre_state, post_state, description).
    """
    trail_name = _extract_resource_name(
        resource_arn
    )
    ct = session.client("cloudtrail")

    # Capture pre-state
    try:
        resp = ct.get_trail(Name=trail_name)
        trail = resp.get("Trail", {})
        pre_state = {
            "IsMultiRegionTrail": trail.get(
                "IsMultiRegionTrail", False
            ),
        }
    except Exception:
        pre_state = {
            "IsMultiRegionTrail": False,
        }

    # Apply fix
    ct.update_trail(
        Name=trail_name,
        IsMultiRegionTrail=True,
    )

    post_state = {"IsMultiRegionTrail": True}

    return (
        pre_state,
        post_state,
        f"Enabled multi-region on trail "
        f"{trail_name}",
    )


def _fix_security_group_port(
    session: boto3.Session,
    resource_arn: str,
    port: int,
    label: str,
) -> tuple[dict, dict, str]:
    """Revoke open ingress rules for a port.

    Removes both IPv4 0.0.0.0/0 and IPv6 ::/0
    ingress rules, including all-traffic (-1).

    Args:
        session: boto3 session.
        resource_arn: Security group ARN.
        port: Port number to close (22, 3389).
        label: Human label (SSH, RDP).

    Returns:
        Tuple of (pre_state, post_state, desc).
    """
    sg_id = _extract_resource_name(resource_arn)
    ec2 = session.client("ec2")

    resp = ec2.describe_security_groups(
        GroupIds=[sg_id]
    )
    sg = resp["SecurityGroups"][0]
    pre_rules = sg.get("IpPermissions", [])
    pre_state = {"IpPermissions": pre_rules}

    for rule in pre_rules:
        proto = rule.get("IpProtocol", "tcp")
        from_port = rule.get("FromPort", 0)
        to_port = rule.get("ToPort", 0)
        matches = (
            proto == "-1"
            or from_port <= port <= to_port
        )
        if not matches:
            continue
        for ip_range in rule.get(
            "IpRanges", []
        ):
            if (
                ip_range.get("CidrIp")
                == "0.0.0.0/0"
            ):
                ec2.revoke_security_group_ingress(
                    GroupId=sg_id,
                    IpPermissions=[
                        {
                            "IpProtocol": proto,
                            "FromPort": from_port,
                            "ToPort": to_port,
                            "IpRanges": [
                                {
                                    "CidrIp": (
                                        "0.0.0.0/0"
                                    )
                                }
                            ],
                        }
                    ],
                )
        for ip_range in rule.get(
            "Ipv6Ranges", []
        ):
            if (
                ip_range.get("CidrIpv6")
                == "::/0"
            ):
                ec2.revoke_security_group_ingress(
                    GroupId=sg_id,
                    IpPermissions=[
                        {
                            "IpProtocol": proto,
                            "FromPort": from_port,
                            "ToPort": to_port,
                            "Ipv6Ranges": [
                                {
                                    "CidrIpv6": (
                                        "::/0"
                                    )
                                }
                            ],
                        }
                    ],
                )

    resp = ec2.describe_security_groups(
        GroupIds=[sg_id]
    )
    post_rules = resp["SecurityGroups"][0].get(
        "IpPermissions", []
    )
    post_state = {"IpPermissions": post_rules}

    return (
        pre_state,
        post_state,
        f"Removed open {label} access from "
        f"{sg_id}",
    )


def _fix_security_group_ssh(
    session: boto3.Session,
    resource_arn: str,
) -> tuple[dict, dict, str]:
    """REM_07: Remove open SSH (port 22) access."""
    return _fix_security_group_port(
        session, resource_arn, 22, "SSH"
    )


def _fix_security_group_rdp(
    session: boto3.Session,
    resource_arn: str,
) -> tuple[dict, dict, str]:
    """REM_07b: Remove open RDP (port 3389) access."""
    return _fix_security_group_port(
        session, resource_arn, 3389, "RDP"
    )


def _fix_imdsv2(
    session: boto3.Session,
    resource_arn: str,
) -> tuple[dict, dict, str]:
    """REM_08: Enforce IMDSv2 on EC2 instance.

    Args:
        session: boto3 session.
        resource_arn: EC2 instance ARN.

    Returns:
        Tuple of (pre_state, post_state, description).
    """
    instance_id = _extract_resource_name(
        resource_arn
    )
    ec2 = session.client("ec2")

    # Capture pre-state
    try:
        resp = ec2.describe_instances(
            InstanceIds=[instance_id]
        )
        instance = resp["Reservations"][0][
            "Instances"
        ][0]
        meta_opts = instance.get(
            "MetadataOptions", {}
        ) or {}
        pre_state = {
            "HttpTokens": meta_opts.get(
                "HttpTokens", "optional"
            ),
            "HttpEndpoint": meta_opts.get(
                "HttpEndpoint", "enabled"
            ),
        }
    except Exception:
        pre_state = {
            "HttpTokens": "optional",
            "HttpEndpoint": "enabled",
        }

    # Apply fix
    ec2.modify_instance_metadata_options(
        InstanceId=instance_id,
        HttpTokens="required",
        HttpEndpoint="enabled",
    )

    post_state = {
        "HttpTokens": "required",
        "HttpEndpoint": "enabled",
    }

    return (
        pre_state,
        post_state,
        f"Enforced IMDSv2 on {instance_id}",
    )


def _fix_ebs_encryption(
    session: boto3.Session,
    resource_arn: str,
) -> tuple[dict, dict, str]:
    """REM_17: Enable EBS default encryption.

    Args:
        session: boto3 session.
        resource_arn: Account-level (region ARN).

    Returns:
        Tuple of (pre_state, post_state, description).
    """
    ec2 = session.client("ec2")

    # Capture pre-state
    resp = ec2.get_ebs_encryption_by_default()
    pre_state = {
        "EbsEncryptionByDefault": resp.get(
            "EbsEncryptionByDefault", False
        ),
    }

    # Apply fix
    ec2.enable_ebs_encryption_by_default()

    post_state = {"EbsEncryptionByDefault": True}

    return (
        pre_state,
        post_state,
        "Enabled EBS default encryption",
    )


# Executor registry
_EXECUTORS: dict[str, Callable] = {
    "REM_04": _fix_s3_public_access,
    "REM_05": _fix_cloudtrail_multiregion,
    "REM_07": _fix_security_group_ssh,
    "REM_07b": _fix_security_group_rdp,
    "REM_08": _fix_imdsv2,
    "REM_17": _fix_ebs_encryption,
}
