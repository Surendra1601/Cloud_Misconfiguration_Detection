"""DynamoDB config manager for auto-remediation.

Handles CRUD operations against the
auto-remediation-config table, controlling which
checks are eligible for automatic remediation
per account.
"""

import logging
from datetime import UTC, datetime

import boto3
from boto3.dynamodb.conditions import Key

from app.pipeline.remediation.models import (
    AutoRemediationConfig,
)

logger = logging.getLogger(__name__)


class ConfigManager:
    """Manages auto-remediation configuration in DynamoDB.

    Table schema:
        pk: {account_id}
        sk: {check_id}

    Attributes:
        table: DynamoDB Table resource.
        table_name: Name of the DynamoDB table.

    Example:
        >>> session = boto3.Session()
        >>> mgr = ConfigManager(session)
        >>> mgr.table_name
        'auto-remediation-config'
    """

    def __init__(
        self,
        session: boto3.Session,
        table_name: str = (
            "auto-remediation-config"
        ),
        endpoint_url: str | None = None,
    ) -> None:
        """Initialize ConfigManager.

        Args:
            session: boto3 session.
            table_name: DynamoDB table name.
            endpoint_url: Optional DynamoDB Local
                endpoint.
        """
        kwargs: dict = {}
        if endpoint_url:
            kwargs["endpoint_url"] = endpoint_url
        dynamodb = session.resource(
            "dynamodb", **kwargs
        )
        self.table = dynamodb.Table(table_name)
        self.table_name = table_name

    def get_config(
        self,
        account_id: str,
        check_id: str,
    ) -> AutoRemediationConfig | None:
        """Get auto-remediation config for a check.

        Args:
            account_id: AWS account ID.
            check_id: Policy check ID.

        Returns:
            Config if found, None otherwise.
        """
        try:
            resp = self.table.get_item(
                Key={
                    "pk": account_id,
                    "sk": check_id,
                }
            )
            item = resp.get("Item")
            if not item:
                return None
            return _item_to_config(item)
        except Exception as e:
            logger.error(
                "get_config error: %s", e
            )
            return None

    def set_config(
        self, config: AutoRemediationConfig
    ) -> bool:
        """Create or update auto-remediation config.

        Args:
            config: Configuration to persist.

        Returns:
            True on success, False on failure.
        """
        item = {
            "pk": config.account_id,
            "sk": config.check_id,
            "enabled": config.enabled,
            "rollback_window_minutes": (
                config.rollback_window_minutes
            ),
            "notify_on_action": (
                config.notify_on_action
            ),
            "approved_by": config.approved_by,
            "approved_at": (
                config.approved_at
                or datetime.now(UTC).isoformat()
            ),
        }
        try:
            self.table.put_item(Item=item)
            logger.info(
                "Set auto-remediation config: "
                "%s/%s enabled=%s",
                config.account_id,
                config.check_id,
                config.enabled,
            )
            return True
        except Exception as e:
            logger.error(
                "set_config error: %s", e
            )
            return False

    def delete_config(
        self,
        account_id: str,
        check_id: str,
    ) -> bool:
        """Delete auto-remediation config for a check.

        Args:
            account_id: AWS account ID.
            check_id: Policy check ID.

        Returns:
            True on success, False on failure.
        """
        try:
            self.table.delete_item(
                Key={
                    "pk": account_id,
                    "sk": check_id,
                }
            )
            return True
        except Exception as e:
            logger.error(
                "delete_config error: %s", e
            )
            return False

    def list_configs(
        self,
        account_id: str,
        enabled_only: bool = False,
    ) -> list[AutoRemediationConfig]:
        """List all configs for an account.

        Args:
            account_id: AWS account ID.
            enabled_only: If True, only return enabled.

        Returns:
            List of AutoRemediationConfig records.
        """
        try:
            items = []
            kwargs = {
                "KeyConditionExpression": (
                    Key("pk").eq(account_id)
                ),
            }
            while True:
                resp = self.table.query(**kwargs)
                items.extend(
                    resp.get("Items", [])
                )
                lek = resp.get(
                    "LastEvaluatedKey"
                )
                if not lek:
                    break
                kwargs["ExclusiveStartKey"] = lek
            configs = [
                _item_to_config(i)
                for i in items
            ]
            if enabled_only:
                configs = [
                    c for c in configs if c.enabled
                ]
            return configs
        except Exception as e:
            logger.error(
                "list_configs error: %s", e
            )
            return []

    def is_enabled(
        self,
        account_id: str,
        check_id: str,
    ) -> bool:
        """Check if auto-remediation is enabled.

        Args:
            account_id: AWS account ID.
            check_id: Policy check ID.

        Returns:
            True if enabled, False otherwise.
        """
        config = self.get_config(
            account_id, check_id
        )
        return config is not None and config.enabled

    def count_enabled(
        self, account_id: str
    ) -> int:
        """Count enabled auto-remediation configs.

        Args:
            account_id: AWS account ID.

        Returns:
            Number of enabled configs.
        """
        configs = self.list_configs(
            account_id, enabled_only=True
        )
        return len(configs)


def _item_to_config(
    item: dict,
) -> AutoRemediationConfig:
    """Convert DynamoDB item to AutoRemediationConfig.

    Args:
        item: Raw DynamoDB item dict.

    Returns:
        AutoRemediationConfig model instance.
    """
    return AutoRemediationConfig(
        account_id=item.get("pk", ""),
        check_id=item.get("sk", ""),
        enabled=item.get("enabled", False),
        rollback_window_minutes=int(
            item.get("rollback_window_minutes", 60)
        ),
        notify_on_action=item.get(
            "notify_on_action", True
        ),
        approved_by=item.get("approved_by", ""),
        approved_at=item.get("approved_at", ""),
    )
