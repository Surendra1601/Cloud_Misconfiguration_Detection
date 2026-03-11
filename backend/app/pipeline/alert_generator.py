"""Alert generator — publishes drift alerts to SNS.

Formats DriftAlert objects as JSON and publishes to
an SNS topic for downstream consumers (Slack,
PagerDuty, email, WebSocket).
"""

import json
import logging

import boto3

from app.pipeline.models import DriftAlert, DriftType

logger = logging.getLogger(__name__)

# Only these drift types trigger an SNS notification
_ALERTABLE_TYPES = {
    DriftType.NEW_VIOLATION,
    DriftType.RESOLUTION,
}


class AlertGenerator:
    """Publishes drift alerts to an SNS topic.

    Silently skips publishing when no topic ARN is
    configured, allowing local development without SNS.

    Example:
        >>> gen = AlertGenerator(
        ...     session=boto3.Session(),
        ...     topic_arn="arn:aws:sns:us-east-1:...",
        ... )
        >>> gen.publish(drift_alert)
        True
    """

    def __init__(
        self,
        session: boto3.Session,
        topic_arn: str = "",
        endpoint_url: str | None = None,
    ):
        self.topic_arn = topic_arn
        self._client = None
        self._session = session
        self._endpoint_url = endpoint_url

    @property
    def client(self):
        """Lazy-init SNS client."""
        if self._client is None:
            kwargs = {}
            if self._endpoint_url:
                kwargs["endpoint_url"] = (
                    self._endpoint_url
                )
            self._client = self._session.client(
                "sns", **kwargs
            )
        return self._client

    def publish(self, alert: DriftAlert) -> bool:
        """Publish a drift alert to SNS.

        Only publishes for new_violation and resolution
        drift types. Skips no_change and first_seen.

        Args:
            alert: The DriftAlert to publish.

        Returns:
            True if published (or skipped by design),
            False if publish failed.
        """
        if not self.topic_arn:
            logger.debug(
                "No SNS topic configured, skipping"
            )
            return False

        if alert.drift_type not in _ALERTABLE_TYPES:
            logger.debug(
                "Skipping non-alertable type: %s",
                alert.drift_type.value,
            )
            return False

        message = self._format_message(alert)
        subject = self._format_subject(alert)

        try:
            self.client.publish(
                TopicArn=self.topic_arn,
                Message=json.dumps(
                    message, default=str
                ),
                Subject=subject,
                MessageAttributes=self._attributes(
                    alert
                ),
            )
            logger.info(
                "Published %s alert for %s %s",
                alert.drift_type.value,
                alert.check_id,
                alert.resource_arn,
            )
            return True
        except Exception as e:
            logger.error(
                "SNS publish failed: %s", e
            )
            return False

    def publish_batch(
        self, alerts: list[DriftAlert]
    ) -> int:
        """Publish multiple alerts. Returns count of
        successfully published alerts."""
        count = 0
        for alert in alerts:
            if self.publish(alert):
                count += 1
        return count

    def _format_message(
        self, alert: DriftAlert
    ) -> dict:
        """Build the SNS message payload."""
        return {
            "type": alert.drift_type.value,
            "check_id": alert.check_id,
            "resource_arn": alert.resource_arn,
            "previous_status": alert.previous_status,
            "current_status": alert.current_status,
            "severity": alert.severity.value,
            "risk_score": alert.risk_score,
            "trigger_event": alert.trigger_event,
            "timestamp": alert.timestamp,
            "reason": alert.reason,
            "account_id": alert.account_id,
            "region": alert.region,
        }

    def _format_subject(
        self, alert: DriftAlert
    ) -> str:
        """Build a short SNS subject line (max 100)."""
        if alert.drift_type == DriftType.NEW_VIOLATION:
            prefix = "VIOLATION"
        else:
            prefix = "RESOLVED"

        subject = (
            f"[{prefix}] {alert.check_id} "
            f"({alert.severity.value})"
        )
        return subject[:100]

    def _attributes(
        self, alert: DriftAlert
    ) -> dict:
        """Build SNS MessageAttributes for filtering."""
        return {
            "drift_type": {
                "DataType": "String",
                "StringValue": alert.drift_type.value,
            },
            "severity": {
                "DataType": "String",
                "StringValue": alert.severity.value,
            },
            "check_id": {
                "DataType": "String",
                "StringValue": alert.check_id,
            },
        }
