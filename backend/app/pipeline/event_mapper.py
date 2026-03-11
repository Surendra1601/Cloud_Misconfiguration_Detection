"""Maps CloudTrail event names to collectors and policies.

Each CloudTrail API event is mapped to the collector that
can fetch the affected resource and the Rego policies that
should be re-evaluated.
"""

import logging

from app.pipeline.models import EventMapping

logger = logging.getLogger(__name__)

EVENT_POLICY_MAP: dict[str, dict] = {
    # --- S3 events -> Check 04 ---
    "CreateBucket": {
        "collector": "s3",
        "policies": [
            "check_04_s3_public_access",
        ],
    },
    "PutBucketPublicAccessBlock": {
        "collector": "s3",
        "policies": [
            "check_04_s3_public_access",
        ],
    },
    "PutBucketPolicy": {
        "collector": "s3",
        "policies": [
            "check_04_s3_public_access",
        ],
    },
    "PutBucketEncryption": {
        "collector": "s3",
        "policies": [
            "check_04_s3_public_access",
        ],
    },
    "DeleteBucketEncryption": {
        "collector": "s3",
        "policies": [
            "check_04_s3_public_access",
        ],
    },
    "DeleteBucket": {
        "collector": "s3",
        "policies": [
            "check_04_s3_public_access",
        ],
    },
    "DeleteBucketPolicy": {
        "collector": "s3",
        "policies": [
            "check_04_s3_public_access",
        ],
    },
    "DeletePublicAccessBlock": {
        "collector": "s3",
        "policies": [
            "check_04_s3_public_access",
        ],
    },
    # --- Security Group events -> Check 07 ---
    "AuthorizeSecurityGroupIngress": {
        "collector": "ec2",
        "policies": [
            "check_07_security_groups",
            "capital_one_scenario",
        ],
    },
    "RevokeSecurityGroupIngress": {
        "collector": "ec2",
        "policies": [
            "check_07_security_groups",
        ],
    },
    "CreateSecurityGroup": {
        "collector": "ec2",
        "policies": [
            "check_07_security_groups",
        ],
    },
    "DeleteSecurityGroup": {
        "collector": "ec2",
        "policies": [
            "check_07_security_groups",
        ],
    },
    # --- IAM events -> Checks 01-03, 10, 19 ---
    "CreateUser": {
        "collector": "iam",
        "policies": [
            "check_03_mfa_all_users",
            "check_10_unused_credentials",
        ],
    },
    "CreateAccessKey": {
        "collector": "iam",
        "policies": [
            "check_10_unused_credentials",
        ],
    },
    "DeleteAccessKey": {
        "collector": "iam",
        "policies": [
            "check_10_unused_credentials",
        ],
    },
    "DeleteUser": {
        "collector": "iam",
        "policies": [
            "check_03_mfa_all_users",
            "check_10_unused_credentials",
        ],
    },
    "AttachRolePolicy": {
        "collector": "iam",
        "policies": [
            "check_19_access_analyzer",
            "capital_one_scenario",
        ],
    },
    "UpdateAccountPasswordPolicy": {
        "collector": "iam",
        "policies": [
            "check_02_password_policy",
        ],
    },
    "DetachRolePolicy": {
        "collector": "iam",
        "policies": [
            "check_19_access_analyzer",
        ],
    },
    "DeleteRolePolicy": {
        "collector": "iam",
        "policies": [
            "check_19_access_analyzer",
        ],
    },
    # --- EC2 events -> Check 08 ---
    "RunInstances": {
        "collector": "ec2",
        "policies": [
            "check_08_ec2_security",
            "capital_one_scenario",
        ],
    },
    "ModifyInstanceMetadataOptions": {
        "collector": "ec2",
        "policies": [
            "check_08_ec2_security",
            "capital_one_scenario",
        ],
    },
    "TerminateInstances": {
        "collector": "ec2",
        "policies": [
            "check_08_ec2_security",
        ],
    },
    "ModifyInstanceAttribute": {
        "collector": "ec2",
        "policies": [
            "check_08_ec2_security",
        ],
    },
    # --- CloudTrail events -> Check 05 ---
    "StartLogging": {
        "collector": "logging",
        "policies": [
            "check_05_cloudtrail",
        ],
    },
    "CreateTrail": {
        "collector": "logging",
        "policies": [
            "check_05_cloudtrail",
        ],
    },
    "StopLogging": {
        "collector": "logging",
        "policies": [
            "check_05_cloudtrail",
        ],
    },
    "DeleteTrail": {
        "collector": "logging",
        "policies": [
            "check_05_cloudtrail",
        ],
    },
    # --- RDS events -> Check 09 ---
    "CreateDBInstance": {
        "collector": "rds",
        "policies": [
            "check_09_rds_security",
        ],
    },
    "ModifyDBInstance": {
        "collector": "rds",
        "policies": [
            "check_09_rds_security",
        ],
    },
    "DeleteDBInstance": {
        "collector": "rds",
        "policies": [
            "check_09_rds_security",
        ],
    },
    # --- Lambda events -> Check 14 ---
    "CreateFunction20150331": {
        "collector": "lambda",
        "policies": [
            "check_14_lambda_security",
        ],
    },
    "DeleteFunction20150331": {
        "collector": "lambda",
        "policies": [
            "check_14_lambda_security",
        ],
    },
    "UpdateFunctionConfiguration20150331v2": {
        "collector": "lambda",
        "policies": [
            "check_14_lambda_security",
        ],
    },
    # --- EBS events -> Check 17 ---
    "CreateVolume": {
        "collector": "ec2",
        "policies": [
            "check_17_ebs_encryption",
        ],
    },
    "DeleteVolume": {
        "collector": "ec2",
        "policies": [
            "check_17_ebs_encryption",
        ],
    },
    # --- VPC Flow Logs -> Check 06 ---
    "CreateFlowLogs": {
        "collector": "vpc",
        "policies": [
            "check_06_vpc_flow_logs",
        ],
    },
    "DeleteFlowLogs": {
        "collector": "vpc",
        "policies": [
            "check_06_vpc_flow_logs",
        ],
    },
    # --- GuardDuty events -> Check 13 ---
    "CreateDetector": {
        "collector": "logging",
        "policies": [
            "check_13_guardduty",
        ],
    },
    "DeleteDetector": {
        "collector": "logging",
        "policies": [
            "check_13_guardduty",
        ],
    },
}

# Reverse lookup: collector -> list of event names
COLLECTOR_EVENTS: dict[str, list[str]] = {}
for _evt, _mapping in EVENT_POLICY_MAP.items():
    _collector = _mapping["collector"]
    if _collector not in COLLECTOR_EVENTS:
        COLLECTOR_EVENTS[_collector] = []
    COLLECTOR_EVENTS[_collector].append(_evt)


def get_event_mapping(
    event_name: str,
) -> EventMapping | None:
    """Look up collector and policies for an event.

    Args:
        event_name: CloudTrail API event name,
            e.g. "CreateBucket".

    Returns:
        EventMapping with collector and policies,
        or None if event is not tracked.

    Example:
        >>> m = get_event_mapping("CreateBucket")
        >>> m.collector
        's3'
        >>> "check_04_s3_public_access" in m.policies
        True
    """
    raw = EVENT_POLICY_MAP.get(event_name)
    if raw is None:
        logger.debug(
            "Untracked event: %s", event_name
        )
        return None
    return EventMapping(
        collector=raw["collector"],
        policies=raw["policies"],
    )


def is_tracked_event(event_name: str) -> bool:
    """Check if an event name is tracked.

    Args:
        event_name: CloudTrail API event name.

    Returns:
        True if the event is in EVENT_POLICY_MAP.

    Example:
        >>> is_tracked_event("CreateBucket")
        True
        >>> is_tracked_event("DescribeBuckets")
        False
    """
    return event_name in EVENT_POLICY_MAP


def get_tracked_events() -> list[str]:
    """Return all tracked event names.

    Returns:
        Sorted list of all CloudTrail event names
        in EVENT_POLICY_MAP.

    Example:
        >>> events = get_tracked_events()
        >>> "CreateBucket" in events
        True
    """
    return sorted(EVENT_POLICY_MAP.keys())


def get_events_for_collector(
    collector: str,
) -> list[str]:
    """Return event names handled by a collector.

    Args:
        collector: Collector module name
            (e.g. "s3", "iam").

    Returns:
        List of event names for that collector.

    Example:
        >>> evts = get_events_for_collector("s3")
        >>> "CreateBucket" in evts
        True
    """
    return COLLECTOR_EVENTS.get(collector, [])
