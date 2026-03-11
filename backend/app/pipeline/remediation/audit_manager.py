"""DynamoDB audit trail for remediation actions.

Handles CRUD operations against the remediation-audit
table, including queries by account, check, and time.
"""

import logging
import uuid
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import boto3
from boto3.dynamodb.conditions import (
    Attr,
    Key,
)

from app.pipeline.remediation.models import (
    RemediationAuditEntry,
    RemediationStatus,
    RemediationTier,
)

logger = logging.getLogger(__name__)


class AuditManager:
    """Manages remediation audit trail in DynamoDB.

    Table schema:
        pk: {account_id}
        sk: {timestamp}#{remediation_id}

    Attributes:
        table: DynamoDB Table resource.
        table_name: Name of the DynamoDB table.

    Example:
        >>> session = boto3.Session()
        >>> mgr = AuditManager(session)
        >>> mgr.table_name
        'remediation-audit'
    """

    def __init__(
        self,
        session: boto3.Session,
        table_name: str = "remediation-audit",
        endpoint_url: str | None = None,
    ) -> None:
        """Initialize AuditManager.

        Args:
            session: boto3 session.
            table_name: DynamoDB table name.
            endpoint_url: Optional endpoint for
                DynamoDB Local.
        """
        kwargs: dict = {}
        if endpoint_url:
            kwargs["endpoint_url"] = endpoint_url
        dynamodb = session.resource(
            "dynamodb", **kwargs
        )
        self.table = dynamodb.Table(table_name)
        self.table_name = table_name

    def record_action(
        self,
        account_id: str,
        remediation_id: str,
        check_id: str,
        resource_arn: str,
        action_taken: str,
        tier: RemediationTier,
        initiated_by: str,
        approved_by: str = "",
        status: RemediationStatus = (
            RemediationStatus.EXECUTED
        ),
        pre_state: dict | None = None,
        post_state: dict | None = None,
        rollback_window_minutes: int = 60,
    ) -> str:
        """Write a remediation audit entry.

        Args:
            account_id: AWS account ID.
            remediation_id: Template ID (e.g. REM_04).
            check_id: Policy check ID.
            resource_arn: Target resource ARN.
            action_taken: Description of fix applied.
            tier: Remediation tier used.
            initiated_by: User email or SYSTEM.
            approved_by: Approver or policy name.
            status: Action outcome.
            pre_state: Config before fix.
            post_state: Config after fix.
            rollback_window_minutes: Rollback window.

        Returns:
            The generated action_id.

        Raises:
            Exception: On DynamoDB write failure.
        """
        now = datetime.now(UTC)
        ts = now.isoformat()
        action_id = (
            f"rem-{now.strftime('%Y%m%d%H%M%S')}"
            f"-{uuid.uuid4().hex[:8]}"
        )
        rollback_deadline = (
            now
            + timedelta(minutes=rollback_window_minutes)
        ).isoformat()

        item = {
            "pk": account_id,
            "sk": f"{ts}#{remediation_id}",
            "action_id": action_id,
            "remediation_id": remediation_id,
            "check_id": check_id,
            "resource_arn": resource_arn,
            "action_taken": action_taken,
            "tier": tier.value,
            "initiated_by": initiated_by,
            "approved_by": approved_by,
            "status": status.value,
            "rollback_deadline": rollback_deadline,
            "pre_state": _sanitize_for_dynamo(
                pre_state or {}
            ),
            "post_state": _sanitize_for_dynamo(
                post_state or {}
            ),
            "created_at": ts,
        }

        try:
            self.table.put_item(Item=item)
            logger.info(
                "Recorded remediation action %s "
                "for %s on %s",
                action_id,
                remediation_id,
                resource_arn,
            )
            return action_id
        except Exception as e:
            logger.error(
                "record_action error: %s", e
            )
            raise

    def get_action(
        self,
        account_id: str,
        action_id: str,
    ) -> RemediationAuditEntry | None:
        """Look up an action by account + action_id.

        Paginates across 1MB boundaries since
        action_id is a filter (not sort key).
        """
        try:
            kwargs = {
                "KeyConditionExpression": (
                    Key("pk").eq(account_id)
                ),
                "FilterExpression": (
                    Attr("action_id").eq(
                        action_id
                    )
                ),
            }
            while True:
                resp = self.table.query(**kwargs)
                items = resp.get("Items", [])
                if items:
                    return _item_to_entry(items[0])
                lek = resp.get(
                    "LastEvaluatedKey"
                )
                if not lek:
                    return None
                kwargs["ExclusiveStartKey"] = lek
        except Exception as e:
            logger.error(
                "get_action error: %s", e
            )
            return None

    def list_actions(
        self,
        account_id: str,
        since: str | None = None,
        check_id: str | None = None,
        limit: int = 100,
    ) -> list[RemediationAuditEntry]:
        """Query audit trail with optional filters.

        Args:
            account_id: AWS account ID.
            since: ISO timestamp to filter from.
            check_id: Optional check_id filter.
            limit: Max items to return.

        Returns:
            List of audit entries, newest first.
        """
        try:
            key_cond = Key("pk").eq(account_id)
            if since:
                key_cond = key_cond & Key("sk").gte(
                    since
                )

            kwargs: dict = {
                "KeyConditionExpression": key_cond,
                "ScanIndexForward": False,
                "Limit": limit,
            }

            if check_id:
                kwargs["FilterExpression"] = (
                    Attr("check_id").eq(check_id)
                )

            items = []
            while True:
                resp = self.table.query(**kwargs)
                items.extend(
                    resp.get("Items", [])
                )
                if len(items) >= limit:
                    items = items[:limit]
                    break
                lek = resp.get(
                    "LastEvaluatedKey"
                )
                if not lek:
                    break
                kwargs["ExclusiveStartKey"] = lek
            return [
                _item_to_entry(i)
                for i in items
            ]
        except Exception as e:
            logger.error(
                "list_actions error: %s", e
            )
            return []

    def update_status(
        self,
        account_id: str,
        sk: str,
        new_status: RemediationStatus,
    ) -> bool:
        """Update the status of an existing action.

        Args:
            account_id: AWS account ID (pk).
            sk: Sort key of the action.
            new_status: New status value.

        Returns:
            True on success, False on failure.
        """
        try:
            self.table.update_item(
                Key={"pk": account_id, "sk": sk},
                UpdateExpression=(
                    "SET #st = :new_status"
                ),
                ExpressionAttributeNames={
                    "#st": "status"
                },
                ExpressionAttributeValues={
                    ":new_status": new_status.value
                },
            )
            return True
        except Exception as e:
            logger.error(
                "update_status error: %s", e
            )
            return False

    def count_actions(
        self,
        account_id: str,
    ) -> int:
        """Count total actions for an account.

        Args:
            account_id: AWS account ID.

        Returns:
            Number of audit entries.
        """
        try:
            total = 0
            kwargs = {
                "KeyConditionExpression": (
                    Key("pk").eq(account_id)
                ),
                "Select": "COUNT",
            }
            while True:
                resp = self.table.query(**kwargs)
                total += resp.get("Count", 0)
                lek = resp.get(
                    "LastEvaluatedKey"
                )
                if not lek:
                    break
                kwargs["ExclusiveStartKey"] = lek
            return total
        except Exception as e:
            logger.error(
                "count_actions error: %s", e
            )
            return 0


def _sanitize_for_dynamo(data: dict) -> dict:
    """Convert floats to Decimals for DynamoDB.

    Args:
        data: Dict potentially containing floats.

    Returns:
        Dict safe for DynamoDB storage.
    """
    result = {}
    for k, v in data.items():
        if isinstance(v, float):
            result[k] = Decimal(str(v))
        elif isinstance(v, dict):
            result[k] = _sanitize_for_dynamo(v)
        elif isinstance(v, list):
            result[k] = [
                (
                    _sanitize_for_dynamo(i)
                    if isinstance(i, dict)
                    else i
                )
                for i in v
            ]
        else:
            result[k] = v
    return result


def _item_to_entry(
    item: dict,
) -> RemediationAuditEntry:
    """Convert DynamoDB item to RemediationAuditEntry.

    Args:
        item: Raw DynamoDB item dict.

    Returns:
        RemediationAuditEntry model instance.
    """
    return RemediationAuditEntry(
        action_id=item.get("action_id", ""),
        account_id=item.get("pk", ""),
        remediation_id=item.get(
            "remediation_id", ""
        ),
        check_id=item.get("check_id", ""),
        resource_arn=item.get("resource_arn", ""),
        action_taken=item.get("action_taken", ""),
        tier=RemediationTier(
            item.get(
                "tier",
                RemediationTier.ONE_CLICK.value,
            )
        ),
        initiated_by=item.get("initiated_by", ""),
        approved_by=item.get("approved_by", ""),
        status=RemediationStatus(
            item.get(
                "status",
                RemediationStatus.PENDING.value,
            )
        ),
        rollback_deadline=item.get(
            "rollback_deadline", ""
        ),
        pre_state=item.get("pre_state", {}),
        post_state=item.get("post_state", {}),
        created_at=item.get("created_at", ""),
    )
