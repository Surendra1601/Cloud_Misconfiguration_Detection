"""Tests for AuditManager DynamoDB CRUD operations."""

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

import boto3
import pytest
from moto import mock_aws

from app.pipeline.remediation.audit_manager import (
    AuditManager,
    _item_to_entry,
    _sanitize_for_dynamo,
)
from app.pipeline.remediation.models import (
    RemediationAuditEntry,
    RemediationStatus,
    RemediationTier,
)

ACCOUNT = "123456789012"
TABLE_NAME = "remediation-audit"


def _create_table(session):
    """Create the remediation-audit table."""
    ddb = session.resource("dynamodb")
    ddb.create_table(
        TableName=TABLE_NAME,
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
def audit_mgr(aws_credentials):
    """Create AuditManager with mocked DynamoDB."""
    with mock_aws():
        session = boto3.Session(
            region_name="us-east-1"
        )
        _create_table(session)
        yield AuditManager(
            session=session,
            table_name=TABLE_NAME,
        )


class TestRecordAction:
    """Test writing audit entries."""

    def test_record_returns_action_id(self, audit_mgr):
        action_id = audit_mgr.record_action(
            account_id=ACCOUNT,
            remediation_id="REM_04",
            check_id="CHECK_04",
            resource_arn="arn:aws:s3:::bucket",
            action_taken="Blocked public access",
            tier=RemediationTier.ONE_CLICK,
            initiated_by="user@example.com",
        )
        assert action_id.startswith("rem-")

    def test_record_action_id_unique(self, audit_mgr):
        ids = set()
        for _ in range(5):
            aid = audit_mgr.record_action(
                account_id=ACCOUNT,
                remediation_id="REM_04",
                check_id="CHECK_04",
                resource_arn="arn:aws:s3:::bucket",
                action_taken="Fix",
                tier=RemediationTier.ONE_CLICK,
                initiated_by="user@example.com",
            )
            ids.add(aid)
        assert len(ids) == 5

    def test_record_with_pre_post_state(
        self, audit_mgr
    ):
        action_id = audit_mgr.record_action(
            account_id=ACCOUNT,
            remediation_id="REM_04",
            check_id="CHECK_04",
            resource_arn="arn:aws:s3:::bucket",
            action_taken="Blocked public access",
            tier=RemediationTier.ONE_CLICK,
            initiated_by="user@example.com",
            pre_state={"BlockPublicAcls": False},
            post_state={"BlockPublicAcls": True},
        )
        entry = audit_mgr.get_action(
            ACCOUNT, action_id
        )
        assert entry is not None
        assert entry.pre_state["BlockPublicAcls"] is (
            False
        )
        assert entry.post_state["BlockPublicAcls"] is (
            True
        )

    def test_record_tier_3_auto(self, audit_mgr):
        action_id = audit_mgr.record_action(
            account_id=ACCOUNT,
            remediation_id="REM_07",
            check_id="CHECK_07",
            resource_arn="arn:aws:ec2:::sg-abc",
            action_taken="Revoked SSH rule",
            tier=RemediationTier.AUTO,
            initiated_by="SYSTEM",
            approved_by="auto-policy",
        )
        entry = audit_mgr.get_action(
            ACCOUNT, action_id
        )
        assert entry.tier == RemediationTier.AUTO
        assert entry.initiated_by == "SYSTEM"
        assert entry.approved_by == "auto-policy"

    def test_record_failed_status(self, audit_mgr):
        action_id = audit_mgr.record_action(
            account_id=ACCOUNT,
            remediation_id="REM_04",
            check_id="CHECK_04",
            resource_arn="arn:aws:s3:::bucket",
            action_taken="Attempted fix",
            tier=RemediationTier.ONE_CLICK,
            initiated_by="user@example.com",
            status=RemediationStatus.FAILED,
        )
        entry = audit_mgr.get_action(
            ACCOUNT, action_id
        )
        assert (
            entry.status == RemediationStatus.FAILED
        )

    def test_rollback_deadline_set(self, audit_mgr):
        action_id = audit_mgr.record_action(
            account_id=ACCOUNT,
            remediation_id="REM_04",
            check_id="CHECK_04",
            resource_arn="arn:aws:s3:::bucket",
            action_taken="Fix",
            tier=RemediationTier.ONE_CLICK,
            initiated_by="user@example.com",
            rollback_window_minutes=120,
        )
        entry = audit_mgr.get_action(
            ACCOUNT, action_id
        )
        assert entry.rollback_deadline
        deadline = datetime.fromisoformat(
            entry.rollback_deadline
        )
        created = datetime.fromisoformat(
            entry.created_at
        )
        diff = deadline - created
        # Should be ~120 minutes
        assert 119 <= diff.total_seconds() / 60 <= 121

    def test_record_with_float_state(self, audit_mgr):
        """Floats should be converted for DynamoDB."""
        action_id = audit_mgr.record_action(
            account_id=ACCOUNT,
            remediation_id="REM_04",
            check_id="CHECK_04",
            resource_arn="arn:aws:s3:::bucket",
            action_taken="Fix",
            tier=RemediationTier.ONE_CLICK,
            initiated_by="user@example.com",
            pre_state={"score": 85.5},
        )
        entry = audit_mgr.get_action(
            ACCOUNT, action_id
        )
        assert entry is not None


class TestGetAction:
    """Test action retrieval."""

    def test_get_existing(self, audit_mgr):
        action_id = audit_mgr.record_action(
            account_id=ACCOUNT,
            remediation_id="REM_04",
            check_id="CHECK_04",
            resource_arn="arn:aws:s3:::bucket",
            action_taken="Fix",
            tier=RemediationTier.ONE_CLICK,
            initiated_by="user@example.com",
        )
        entry = audit_mgr.get_action(
            ACCOUNT, action_id
        )
        assert entry is not None
        assert entry.action_id == action_id
        assert entry.account_id == ACCOUNT
        assert entry.remediation_id == "REM_04"

    def test_get_missing(self, audit_mgr):
        result = audit_mgr.get_action(
            ACCOUNT, "nonexistent-id"
        )
        assert result is None

    def test_get_wrong_account(self, audit_mgr):
        action_id = audit_mgr.record_action(
            account_id=ACCOUNT,
            remediation_id="REM_04",
            check_id="CHECK_04",
            resource_arn="arn:aws:s3:::bucket",
            action_taken="Fix",
            tier=RemediationTier.ONE_CLICK,
            initiated_by="user@example.com",
        )
        result = audit_mgr.get_action(
            "999999999999", action_id
        )
        assert result is None

    def test_entry_fields_populated(self, audit_mgr):
        action_id = audit_mgr.record_action(
            account_id=ACCOUNT,
            remediation_id="REM_07",
            check_id="CHECK_07",
            resource_arn="arn:aws:ec2:::sg",
            action_taken="Revoked rule",
            tier=RemediationTier.ONE_CLICK,
            initiated_by="user@example.com",
            approved_by="user@example.com",
        )
        entry = audit_mgr.get_action(
            ACCOUNT, action_id
        )
        assert entry.check_id == "CHECK_07"
        assert entry.resource_arn == "arn:aws:ec2:::sg"
        assert entry.action_taken == "Revoked rule"
        assert (
            entry.initiated_by == "user@example.com"
        )
        assert entry.created_at


class TestListActions:
    """Test query with filters."""

    def test_list_all(self, audit_mgr):
        for i in range(3):
            audit_mgr.record_action(
                account_id=ACCOUNT,
                remediation_id=f"REM_0{i+1}",
                check_id=f"CHECK_0{i+1}",
                resource_arn=f"arn:aws:s3:::b{i}",
                action_taken=f"Fix {i}",
                tier=RemediationTier.ONE_CLICK,
                initiated_by="user@example.com",
            )
        results = audit_mgr.list_actions(ACCOUNT)
        assert len(results) == 3

    def test_list_empty_account(self, audit_mgr):
        results = audit_mgr.list_actions(
            "999999999999"
        )
        assert results == []

    def test_list_with_limit(self, audit_mgr):
        for i in range(5):
            audit_mgr.record_action(
                account_id=ACCOUNT,
                remediation_id=f"REM_0{i+1}",
                check_id=f"CHECK_0{i+1}",
                resource_arn=f"arn:aws:s3:::b{i}",
                action_taken=f"Fix {i}",
                tier=RemediationTier.ONE_CLICK,
                initiated_by="user@example.com",
            )
        results = audit_mgr.list_actions(
            ACCOUNT, limit=2
        )
        assert len(results) == 2

    def test_list_filter_by_check_id(self, audit_mgr):
        for rid, cid in [
            ("REM_04", "CHECK_04"),
            ("REM_07", "CHECK_07"),
            ("REM_04", "CHECK_04"),
        ]:
            audit_mgr.record_action(
                account_id=ACCOUNT,
                remediation_id=rid,
                check_id=cid,
                resource_arn="arn:aws:s3:::b",
                action_taken="Fix",
                tier=RemediationTier.ONE_CLICK,
                initiated_by="user@example.com",
            )
        results = audit_mgr.list_actions(
            ACCOUNT, check_id="CHECK_04"
        )
        assert len(results) == 2
        for e in results:
            assert e.check_id == "CHECK_04"

    def test_list_filter_by_since(self, audit_mgr):
        audit_mgr.record_action(
            account_id=ACCOUNT,
            remediation_id="REM_04",
            check_id="CHECK_04",
            resource_arn="arn:aws:s3:::b",
            action_taken="Fix",
            tier=RemediationTier.ONE_CLICK,
            initiated_by="user@example.com",
        )
        # Use a future time so nothing matches
        future = (
            datetime.now(UTC) + timedelta(hours=1)
        ).isoformat()
        results = audit_mgr.list_actions(
            ACCOUNT, since=future
        )
        assert len(results) == 0

    def test_list_ordered_newest_first(
        self, audit_mgr
    ):
        ids = []
        for i in range(3):
            aid = audit_mgr.record_action(
                account_id=ACCOUNT,
                remediation_id=f"REM_0{i+1}",
                check_id=f"CHECK_0{i+1}",
                resource_arn=f"arn:aws:s3:::b{i}",
                action_taken=f"Fix {i}",
                tier=RemediationTier.ONE_CLICK,
                initiated_by="user@example.com",
            )
            ids.append(aid)
        results = audit_mgr.list_actions(ACCOUNT)
        # Newest first (ScanIndexForward=False)
        assert results[0].action_id == ids[-1]


class TestUpdateStatus:
    """Test status updates."""

    def test_update_to_rolled_back(self, audit_mgr):
        action_id = audit_mgr.record_action(
            account_id=ACCOUNT,
            remediation_id="REM_04",
            check_id="CHECK_04",
            resource_arn="arn:aws:s3:::b",
            action_taken="Fix",
            tier=RemediationTier.ONE_CLICK,
            initiated_by="user@example.com",
        )
        # Get the entry to find its sk
        entry = audit_mgr.get_action(
            ACCOUNT, action_id
        )
        # Find the sk via a list query
        all_items = audit_mgr.list_actions(ACCOUNT)
        target = [
            e
            for e in all_items
            if e.action_id == action_id
        ][0]

        # Query raw to get sk
        resp = audit_mgr.table.query(
            KeyConditionExpression=(
                boto3.dynamodb.conditions.Key(
                    "pk"
                ).eq(ACCOUNT)
            ),
        )
        item = [
            i
            for i in resp["Items"]
            if i["action_id"] == action_id
        ][0]
        sk = item["sk"]

        ok = audit_mgr.update_status(
            ACCOUNT,
            sk,
            RemediationStatus.ROLLED_BACK,
        )
        assert ok is True

        updated = audit_mgr.get_action(
            ACCOUNT, action_id
        )
        assert (
            updated.status
            == RemediationStatus.ROLLED_BACK
        )

    def test_update_nonexistent(self, audit_mgr):
        # DynamoDB upserts, so this won't error
        ok = audit_mgr.update_status(
            ACCOUNT,
            "nonexistent-sk",
            RemediationStatus.FAILED,
        )
        assert ok is True


class TestCountActions:
    """Test action counting."""

    def test_count_empty(self, audit_mgr):
        assert audit_mgr.count_actions(ACCOUNT) == 0

    def test_count_after_inserts(self, audit_mgr):
        for i in range(4):
            audit_mgr.record_action(
                account_id=ACCOUNT,
                remediation_id=f"REM_0{i+1}",
                check_id=f"CHECK_0{i+1}",
                resource_arn=f"arn:aws:s3:::b{i}",
                action_taken=f"Fix {i}",
                tier=RemediationTier.ONE_CLICK,
                initiated_by="user@example.com",
            )
        assert audit_mgr.count_actions(ACCOUNT) == 4


class TestErrorHandling:
    """Test error handling paths."""

    def test_get_action_dynamo_error(
        self, aws_credentials
    ):
        with mock_aws():
            session = boto3.Session(
                region_name="us-east-1"
            )
            _create_table(session)
            mgr = AuditManager(
                session=session,
                table_name=TABLE_NAME,
            )
            # Break the table reference
            mgr.table = MagicMock()
            mgr.table.query.side_effect = Exception(
                "DDB error"
            )
            result = mgr.get_action(ACCOUNT, "x")
            assert result is None

    def test_list_actions_dynamo_error(
        self, aws_credentials
    ):
        with mock_aws():
            session = boto3.Session(
                region_name="us-east-1"
            )
            _create_table(session)
            mgr = AuditManager(
                session=session,
                table_name=TABLE_NAME,
            )
            mgr.table = MagicMock()
            mgr.table.query.side_effect = Exception(
                "DDB error"
            )
            result = mgr.list_actions(ACCOUNT)
            assert result == []

    def test_update_status_dynamo_error(
        self, aws_credentials
    ):
        with mock_aws():
            session = boto3.Session(
                region_name="us-east-1"
            )
            _create_table(session)
            mgr = AuditManager(
                session=session,
                table_name=TABLE_NAME,
            )
            mgr.table = MagicMock()
            mgr.table.update_item.side_effect = (
                Exception("DDB error")
            )
            ok = mgr.update_status(
                ACCOUNT,
                "sk",
                RemediationStatus.FAILED,
            )
            assert ok is False

    def test_count_dynamo_error(
        self, aws_credentials
    ):
        with mock_aws():
            session = boto3.Session(
                region_name="us-east-1"
            )
            _create_table(session)
            mgr = AuditManager(
                session=session,
                table_name=TABLE_NAME,
            )
            mgr.table = MagicMock()
            mgr.table.query.side_effect = Exception(
                "DDB error"
            )
            count = mgr.count_actions(ACCOUNT)
            assert count == 0


class TestSanitizeForDynamo:
    """Test float-to-Decimal conversion."""

    def test_converts_floats(self):
        result = _sanitize_for_dynamo(
            {"score": 85.5}
        )
        assert str(result["score"]) == "85.5"

    def test_nested_dict(self):
        result = _sanitize_for_dynamo(
            {"nested": {"val": 1.5}}
        )
        assert str(result["nested"]["val"]) == "1.5"

    def test_list_with_dicts(self):
        result = _sanitize_for_dynamo(
            {"items": [{"v": 2.0}]}
        )
        assert str(result["items"][0]["v"]) == "2.0"

    def test_non_float_unchanged(self):
        result = _sanitize_for_dynamo(
            {"name": "test", "count": 5}
        )
        assert result["name"] == "test"
        assert result["count"] == 5

    def test_empty_dict(self):
        assert _sanitize_for_dynamo({}) == {}


class TestItemToEntry:
    """Test DynamoDB item to model conversion."""

    def test_basic_conversion(self):
        item = {
            "pk": ACCOUNT,
            "sk": "2026-03-01T12:00:00Z#REM_04",
            "action_id": "rem-001",
            "remediation_id": "REM_04",
            "check_id": "CHECK_04",
            "resource_arn": "arn:aws:s3:::b",
            "action_taken": "Fix",
            "tier": "tier_2_oneclick",
            "initiated_by": "user@example.com",
            "approved_by": "",
            "status": "executed",
            "rollback_deadline": (
                "2026-03-01T13:00:00Z"
            ),
            "pre_state": {},
            "post_state": {},
            "created_at": "2026-03-01T12:00:00Z",
        }
        entry = _item_to_entry(item)
        assert isinstance(
            entry, RemediationAuditEntry
        )
        assert entry.account_id == ACCOUNT
        assert entry.remediation_id == "REM_04"
        assert entry.tier == RemediationTier.ONE_CLICK

    def test_missing_fields_use_defaults(self):
        item = {
            "pk": ACCOUNT,
            "action_id": "rem-001",
        }
        entry = _item_to_entry(item)
        assert entry.remediation_id == ""
        assert entry.check_id == ""


class TestEndpointUrl:
    """Test endpoint_url branch in __init__."""

    def test_with_endpoint_url(self, aws_credentials):
        with mock_aws():
            session = boto3.Session(
                region_name="us-east-1"
            )
            _create_table(session)
            mgr = AuditManager(
                session=session,
                table_name=TABLE_NAME,
                endpoint_url=(
                    "http://localhost:8000"
                ),
            )
            assert mgr.table_name == TABLE_NAME


class TestRecordActionException:
    """Test record_action exception path."""

    def test_record_action_reraises(
        self, aws_credentials
    ):
        with mock_aws():
            session = boto3.Session(
                region_name="us-east-1"
            )
            _create_table(session)
            mgr = AuditManager(
                session=session,
                table_name=TABLE_NAME,
            )
            mgr.table = MagicMock()
            mgr.table.put_item.side_effect = (
                Exception("DDB write error")
            )
            with pytest.raises(Exception):
                mgr.record_action(
                    account_id=ACCOUNT,
                    remediation_id="REM_04",
                    check_id="CHECK_04",
                    resource_arn=(
                        "arn:aws:s3:::b"
                    ),
                    action_taken="Fix",
                    tier=RemediationTier.ONE_CLICK,
                    initiated_by="user",
                )
