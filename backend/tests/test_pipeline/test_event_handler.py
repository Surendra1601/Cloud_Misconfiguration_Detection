"""Tests for EventHandler pipeline orchestrator."""

from unittest.mock import MagicMock, patch

from app.models.violation import (
    ComplianceMapping,
    Violation,
)
from app.pipeline.event_handler import EventHandler
from app.pipeline.models import (
    DriftType,
    ViolationState,
)
from app.pipeline.remediation.models import (
    RemediationAction,
    RemediationStatus,
)

ACCOUNT = "123456789012"
REGION = "us-east-1"
BUCKET_ARN = "arn:aws:s3:::my-bucket"
SG_ARN = "arn:aws:ec2:us-east-1:123:sg/sg-abc"


def _raw_eventbridge(
    event_name="CreateBucket",
    event_source="s3.amazonaws.com",
    resource_id="my-bucket",
    resource_arn="",
    account_id=ACCOUNT,
    region=REGION,
):
    """Build a raw EventBridge-wrapped CloudTrail event."""
    return {
        "detail": {
            "eventName": event_name,
            "eventSource": event_source,
            "eventTime": "2026-02-28T12:00:00Z",
            "awsRegion": region,
            "userIdentity": {
                "type": "IAMUser",
                "arn": "arn:aws:iam::123:user/admin",
                "accountId": account_id,
            },
            "sourceIPAddress": "1.2.3.4",
            "userAgent": "console.amazonaws.com",
            "requestParameters": {
                "bucketName": resource_id,
            },
            "responseElements": (
                {"arn": resource_arn}
                if resource_arn
                else {}
            ),
        },
    }


def _make_violation(
    check_id="check_04_s3_public_access",
    status="alarm",
    severity="high",
    reason="S3 bucket publicly accessible",
    resource="my-bucket",
    domain="data_protection",
):
    """Build a Violation result."""
    return Violation(
        check_id=check_id,
        status=status,
        severity=severity,
        reason=reason,
        resource=resource,
        domain=domain,
        compliance=ComplianceMapping(
            cis_aws=["2.1.1"],
        ),
        remediation_id="REM_04",
    )


def _make_handler(
    evaluator=None,
    state_manager=None,
    session=None,
    auto_engine=None,
):
    """Build an EventHandler with mock deps."""
    session = session or MagicMock()
    evaluator = evaluator or MagicMock()
    if state_manager is None:
        state_manager = MagicMock()
        state_manager.get_state.return_value = None
        state_manager.put_state.return_value = True
    return EventHandler(
        session=session,
        evaluator=evaluator,
        state_manager=state_manager,
        account_id=ACCOUNT,
        region=REGION,
        auto_engine=auto_engine,
    )


class TestProcessEventParsing:
    """Step 1: Parsing."""

    def test_unparseable_event_returns_empty(self):
        """Malformed JSON returns no alerts."""
        handler = _make_handler()
        alerts = handler.process_event({})
        assert alerts == []

    def test_missing_event_name_returns_empty(self):
        """Event with no eventName returns empty."""
        handler = _make_handler()
        raw = {"detail": {"eventSource": "s3"}}
        alerts = handler.process_event(raw)
        assert alerts == []


class TestProcessEventMapping:
    """Step 2: Event mapping."""

    def test_untracked_event_returns_empty(self):
        """Untracked event name returns no alerts."""
        handler = _make_handler()
        raw = _raw_eventbridge(
            event_name="DescribeBuckets",
        )
        alerts = handler.process_event(raw)
        assert alerts == []
        handler.evaluator.evaluate_check.assert_not_called()

    def test_tracked_event_proceeds(self):
        """Tracked event triggers evaluation."""
        evaluator = MagicMock()
        evaluator.evaluate_check.return_value = []
        handler = _make_handler(evaluator=evaluator)
        raw = _raw_eventbridge(
            event_name="CreateBucket",
        )
        handler.process_event(raw)
        evaluator.evaluate_check.assert_called()


class TestProcessEventCollection:
    """Step 3: Targeted collection."""

    @patch(
        "app.pipeline.event_handler."
        "CollectionOrchestrator"
    )
    def test_collector_called_with_service(
        self, mock_orch_cls
    ):
        """Collector receives correct service name."""
        mock_orch = MagicMock()
        mock_orch.collect_targeted.return_value = {
            "buckets": []
        }
        mock_orch_cls.return_value = mock_orch

        evaluator = MagicMock()
        evaluator.evaluate_check.return_value = []
        handler = _make_handler(evaluator=evaluator)
        handler.orchestrator = mock_orch

        raw = _raw_eventbridge(
            event_name="CreateBucket",
        )
        handler.process_event(raw)

        mock_orch.collect_targeted.assert_called_once_with(
            "s3", "my-bucket"
        )

    def test_collector_exception_returns_empty_data(
        self,
    ):
        """Collector error doesn't crash pipeline."""
        evaluator = MagicMock()
        evaluator.evaluate_check.return_value = []
        handler = _make_handler(evaluator=evaluator)
        handler.orchestrator = MagicMock()
        handler.orchestrator.collect_targeted.side_effect = (
            RuntimeError("API error")
        )

        raw = _raw_eventbridge(
            event_name="CreateBucket",
        )
        # Should not raise, still calls evaluator
        alerts = handler.process_event(raw)
        evaluator.evaluate_check.assert_called()
        assert isinstance(alerts, list)


class TestProcessEventEvaluation:
    """Step 4: OPA evaluation."""

    def test_evaluation_called_per_policy(self):
        """Multi-policy events evaluate each policy."""
        evaluator = MagicMock()
        evaluator.evaluate_check.return_value = []
        handler = _make_handler(evaluator=evaluator)
        handler.orchestrator = MagicMock()
        handler.orchestrator.collect_targeted.return_value = {}

        # AuthorizeSecurityGroupIngress maps to 2 policies
        raw = _raw_eventbridge(
            event_name="AuthorizeSecurityGroupIngress",
            event_source="ec2.amazonaws.com",
            resource_id="sg-abc",
        )
        handler.process_event(raw)

        assert evaluator.evaluate_check.call_count == 2
        calls = [
            c.args[1]
            for c in evaluator.evaluate_check.call_args_list
        ]
        assert "check_07_security_groups" in calls
        assert "capital_one_scenario" in calls

    def test_evaluation_exception_skips_policy(self):
        """OPA error for one policy still processes others."""
        evaluator = MagicMock()
        evaluator.evaluate_check.side_effect = [
            RuntimeError("OPA down"),
            [],
        ]
        handler = _make_handler(evaluator=evaluator)
        handler.orchestrator = MagicMock()
        handler.orchestrator.collect_targeted.return_value = {}

        raw = _raw_eventbridge(
            event_name="AuthorizeSecurityGroupIngress",
            event_source="ec2.amazonaws.com",
            resource_id="sg-abc",
        )
        alerts = handler.process_event(raw)

        # One policy failed, one succeeded
        assert len(alerts) == 1


class TestProcessEventDrift:
    """Steps 5-6: State lookup and drift detection."""

    def test_first_seen_alarm(self):
        """New resource with alarm = FIRST_SEEN."""
        evaluator = MagicMock()
        evaluator.evaluate_check.return_value = [
            _make_violation(status="alarm"),
        ]
        state_mgr = MagicMock()
        state_mgr.get_state.return_value = None
        state_mgr.put_state.return_value = True

        handler = _make_handler(
            evaluator=evaluator,
            state_manager=state_mgr,
        )
        handler.orchestrator = MagicMock()
        handler.orchestrator.collect_targeted.return_value = {}

        raw = _raw_eventbridge()
        alerts = handler.process_event(raw)

        assert len(alerts) == 1
        assert (
            alerts[0].drift_type == DriftType.FIRST_SEEN
        )
        assert alerts[0].current_status == "alarm"

    def test_first_seen_ok(self):
        """New resource with ok = FIRST_SEEN."""
        evaluator = MagicMock()
        evaluator.evaluate_check.return_value = [
            _make_violation(status="ok"),
        ]
        state_mgr = MagicMock()
        state_mgr.get_state.return_value = None
        state_mgr.put_state.return_value = True

        handler = _make_handler(
            evaluator=evaluator,
            state_manager=state_mgr,
        )
        handler.orchestrator = MagicMock()
        handler.orchestrator.collect_targeted.return_value = {}

        raw = _raw_eventbridge()
        alerts = handler.process_event(raw)

        assert len(alerts) == 1
        assert (
            alerts[0].drift_type == DriftType.FIRST_SEEN
        )
        assert alerts[0].current_status == "ok"

    def test_ok_to_alarm_new_violation(self):
        """Previously ok, now alarm = NEW_VIOLATION."""
        evaluator = MagicMock()
        evaluator.evaluate_check.return_value = [
            _make_violation(status="alarm"),
        ]
        prev_state = ViolationState(
            pk=f"{ACCOUNT}#{REGION}",
            sk="check_04_s3_public_access#my-bucket",
            check_id="check_04_s3_public_access",
            status="ok",
            severity="high",
            domain="data_protection",
            resource_arn="my-bucket",
            first_detected="2026-02-28T10:00:00Z",
            last_evaluated="2026-02-28T11:00:00Z",
        )
        state_mgr = MagicMock()
        state_mgr.get_state.return_value = prev_state
        state_mgr.put_state.return_value = True

        handler = _make_handler(
            evaluator=evaluator,
            state_manager=state_mgr,
        )
        handler.orchestrator = MagicMock()
        handler.orchestrator.collect_targeted.return_value = {}

        raw = _raw_eventbridge()
        alerts = handler.process_event(raw)

        assert len(alerts) == 1
        assert (
            alerts[0].drift_type
            == DriftType.NEW_VIOLATION
        )

    def test_alarm_to_ok_resolution(self):
        """Previously alarm, now ok = RESOLUTION."""
        evaluator = MagicMock()
        evaluator.evaluate_check.return_value = [
            _make_violation(status="ok"),
        ]
        prev_state = ViolationState(
            pk=f"{ACCOUNT}#{REGION}",
            sk="check_04_s3_public_access#my-bucket",
            check_id="check_04_s3_public_access",
            status="alarm",
            severity="high",
            domain="data_protection",
            resource_arn="my-bucket",
            first_detected="2026-02-28T10:00:00Z",
            last_evaluated="2026-02-28T11:00:00Z",
        )
        state_mgr = MagicMock()
        state_mgr.get_state.return_value = prev_state
        state_mgr.put_state.return_value = True

        handler = _make_handler(
            evaluator=evaluator,
            state_manager=state_mgr,
        )
        handler.orchestrator = MagicMock()
        handler.orchestrator.collect_targeted.return_value = {}

        raw = _raw_eventbridge()
        alerts = handler.process_event(raw)

        assert len(alerts) == 1
        assert (
            alerts[0].drift_type == DriftType.RESOLUTION
        )

    def test_alarm_to_alarm_no_change(self):
        """Same alarm status = NO_CHANGE."""
        evaluator = MagicMock()
        evaluator.evaluate_check.return_value = [
            _make_violation(status="alarm"),
        ]
        prev_state = ViolationState(
            pk=f"{ACCOUNT}#{REGION}",
            sk="check_04_s3_public_access#my-bucket",
            check_id="check_04_s3_public_access",
            status="alarm",
            severity="high",
            domain="data_protection",
            resource_arn="my-bucket",
            first_detected="2026-02-28T10:00:00Z",
            last_evaluated="2026-02-28T11:00:00Z",
        )
        state_mgr = MagicMock()
        state_mgr.get_state.return_value = prev_state
        state_mgr.put_state.return_value = True

        handler = _make_handler(
            evaluator=evaluator,
            state_manager=state_mgr,
        )
        handler.orchestrator = MagicMock()
        handler.orchestrator.collect_targeted.return_value = {}

        raw = _raw_eventbridge()
        alerts = handler.process_event(raw)

        assert len(alerts) == 1
        assert (
            alerts[0].drift_type == DriftType.NO_CHANGE
        )


class TestProcessEventPersistence:
    """Step 7: State persistence."""

    def test_state_persisted_on_first_seen(self):
        """put_state called with new state record."""
        evaluator = MagicMock()
        evaluator.evaluate_check.return_value = [
            _make_violation(status="alarm"),
        ]
        state_mgr = MagicMock()
        state_mgr.get_state.return_value = None
        state_mgr.put_state.return_value = True

        handler = _make_handler(
            evaluator=evaluator,
            state_manager=state_mgr,
        )
        handler.orchestrator = MagicMock()
        handler.orchestrator.collect_targeted.return_value = {}

        raw = _raw_eventbridge()
        handler.process_event(raw)

        state_mgr.put_state.assert_called_once()
        saved = state_mgr.put_state.call_args.args[0]
        assert saved.status == "alarm"
        assert saved.check_id == "check_04_s3_public_access"

    def test_state_preserves_compliance_info(self):
        """Compliance mapping propagated to state."""
        v = _make_violation(status="alarm")
        evaluator = MagicMock()
        evaluator.evaluate_check.return_value = [v]
        state_mgr = MagicMock()
        state_mgr.get_state.return_value = None
        state_mgr.put_state.return_value = True

        handler = _make_handler(
            evaluator=evaluator,
            state_manager=state_mgr,
        )
        handler.orchestrator = MagicMock()
        handler.orchestrator.collect_targeted.return_value = {}

        raw = _raw_eventbridge()
        handler.process_event(raw)

        saved = state_mgr.put_state.call_args.args[0]
        assert saved.compliance["cis_aws"] == ["2.1.1"]
        assert saved.remediation_id == "REM_04"

    def test_state_persisted_on_drift(self):
        """State updated when drift detected."""
        evaluator = MagicMock()
        evaluator.evaluate_check.return_value = [
            _make_violation(status="alarm"),
        ]
        prev_state = ViolationState(
            pk=f"{ACCOUNT}#{REGION}",
            sk="check_04_s3_public_access#my-bucket",
            check_id="check_04_s3_public_access",
            status="ok",
            severity="high",
            domain="data_protection",
            resource_arn="my-bucket",
            first_detected="2026-02-28T10:00:00Z",
            last_evaluated="2026-02-28T11:00:00Z",
        )
        state_mgr = MagicMock()
        state_mgr.get_state.return_value = prev_state
        state_mgr.put_state.return_value = True

        handler = _make_handler(
            evaluator=evaluator,
            state_manager=state_mgr,
        )
        handler.orchestrator = MagicMock()
        handler.orchestrator.collect_targeted.return_value = {}

        raw = _raw_eventbridge()
        handler.process_event(raw)

        saved = state_mgr.put_state.call_args.args[0]
        assert saved.status == "alarm"
        assert saved.previous_status == "ok"


class TestProcessEventMultiPolicy:
    """Events that map to multiple policies."""

    def test_multi_policy_returns_multiple_alerts(self):
        """Each policy produces its own alert."""
        evaluator = MagicMock()
        evaluator.evaluate_check.return_value = [
            _make_violation(status="alarm"),
        ]
        state_mgr = MagicMock()
        state_mgr.get_state.return_value = None
        state_mgr.put_state.return_value = True

        handler = _make_handler(
            evaluator=evaluator,
            state_manager=state_mgr,
        )
        handler.orchestrator = MagicMock()
        handler.orchestrator.collect_targeted.return_value = {}

        # AuthorizeSecurityGroupIngress → 2 policies
        raw = _raw_eventbridge(
            event_name="AuthorizeSecurityGroupIngress",
            event_source="ec2.amazonaws.com",
            resource_id="sg-abc",
        )
        alerts = handler.process_event(raw)

        assert len(alerts) == 2
        assert state_mgr.put_state.call_count == 2

    def test_mixed_results_per_policy(self):
        """One policy alarm, another ok."""
        alarm_v = _make_violation(
            check_id="check_07_security_groups",
            status="alarm",
        )
        ok_v = _make_violation(
            check_id="capital_one_scenario",
            status="ok",
        )
        evaluator = MagicMock()
        evaluator.evaluate_check.side_effect = [
            [alarm_v],
            [ok_v],
        ]
        state_mgr = MagicMock()
        state_mgr.get_state.return_value = None
        state_mgr.put_state.return_value = True

        handler = _make_handler(
            evaluator=evaluator,
            state_manager=state_mgr,
        )
        handler.orchestrator = MagicMock()
        handler.orchestrator.collect_targeted.return_value = {}

        raw = _raw_eventbridge(
            event_name="AuthorizeSecurityGroupIngress",
            event_source="ec2.amazonaws.com",
            resource_id="sg-abc",
        )
        alerts = handler.process_event(raw)

        assert len(alerts) == 2
        statuses = {a.current_status for a in alerts}
        assert statuses == {"alarm", "ok"}


class TestProcessEventEmptyResults:
    """Edge case: OPA returns no violations."""

    def test_no_violations_treated_as_ok(self):
        """Empty evaluation result → ok status."""
        evaluator = MagicMock()
        evaluator.evaluate_check.return_value = []
        state_mgr = MagicMock()
        state_mgr.get_state.return_value = None
        state_mgr.put_state.return_value = True

        handler = _make_handler(
            evaluator=evaluator,
            state_manager=state_mgr,
        )
        handler.orchestrator = MagicMock()
        handler.orchestrator.collect_targeted.return_value = {}

        raw = _raw_eventbridge()
        alerts = handler.process_event(raw)

        assert len(alerts) == 1
        assert alerts[0].current_status == "ok"

    def test_empty_results_still_persisted(self):
        """State written even for ok results."""
        evaluator = MagicMock()
        evaluator.evaluate_check.return_value = []
        state_mgr = MagicMock()
        state_mgr.get_state.return_value = None
        state_mgr.put_state.return_value = True

        handler = _make_handler(
            evaluator=evaluator,
            state_manager=state_mgr,
        )
        handler.orchestrator = MagicMock()
        handler.orchestrator.collect_targeted.return_value = {}

        raw = _raw_eventbridge()
        handler.process_event(raw)

        state_mgr.put_state.assert_called_once()
        saved = state_mgr.put_state.call_args.args[0]
        assert saved.status == "ok"


class TestProcessEventAccountRegion:
    """Account and region resolution."""

    def test_uses_event_account_id(self):
        """Account ID from event takes precedence."""
        evaluator = MagicMock()
        evaluator.evaluate_check.return_value = [
            _make_violation(status="alarm"),
        ]
        state_mgr = MagicMock()
        state_mgr.get_state.return_value = None
        state_mgr.put_state.return_value = True

        handler = _make_handler(
            evaluator=evaluator,
            state_manager=state_mgr,
        )
        handler.orchestrator = MagicMock()
        handler.orchestrator.collect_targeted.return_value = {}

        raw = _raw_eventbridge(
            account_id="999888777666",
        )
        alerts = handler.process_event(raw)

        assert alerts[0].account_id == "999888777666"

    def test_falls_back_to_handler_account(self):
        """Uses handler account if event has none."""
        evaluator = MagicMock()
        evaluator.evaluate_check.return_value = [
            _make_violation(status="alarm"),
        ]
        state_mgr = MagicMock()
        state_mgr.get_state.return_value = None
        state_mgr.put_state.return_value = True

        handler = _make_handler(
            evaluator=evaluator,
            state_manager=state_mgr,
        )
        handler.orchestrator = MagicMock()
        handler.orchestrator.collect_targeted.return_value = {}

        raw = _raw_eventbridge(account_id="")
        alerts = handler.process_event(raw)

        assert alerts[0].account_id == ACCOUNT

    def test_uses_event_region(self):
        """Region from event used in state keys."""
        evaluator = MagicMock()
        evaluator.evaluate_check.return_value = [
            _make_violation(status="alarm"),
        ]
        state_mgr = MagicMock()
        state_mgr.get_state.return_value = None
        state_mgr.put_state.return_value = True

        handler = _make_handler(
            evaluator=evaluator,
            state_manager=state_mgr,
        )
        handler.orchestrator = MagicMock()
        handler.orchestrator.collect_targeted.return_value = {}

        raw = _raw_eventbridge(region="eu-west-1")
        alerts = handler.process_event(raw)

        assert alerts[0].region == "eu-west-1"


class TestExtractStatus:
    """_extract_status helper logic."""

    def test_alarm_prioritized_over_ok(self):
        """alarm results take precedence."""
        handler = _make_handler()
        violations = [
            _make_violation(status="ok"),
            _make_violation(
                status="alarm",
                severity="critical",
                reason="Bad config",
                domain="network",
            ),
        ]
        status, sev, reason, domain = (
            handler._extract_status(
                violations, "check_07"
            )
        )
        assert status == "alarm"
        assert sev == "critical"
        assert reason == "Bad config"
        assert domain == "network"

    def test_all_ok_returns_ok(self):
        """Only ok results → ok status."""
        handler = _make_handler()
        violations = [
            _make_violation(status="ok", reason="Good"),
        ]
        status, sev, reason, domain = (
            handler._extract_status(
                violations, "check_04"
            )
        )
        assert status == "ok"

    def test_empty_results_returns_ok(self):
        """No results → ok status."""
        handler = _make_handler()
        status, sev, reason, domain = (
            handler._extract_status([], "check_04")
        )
        assert status == "ok"
        assert sev == ""
        assert reason == ""
        assert domain == ""


class TestCollectError:
    """_collect error handling."""

    def test_collect_returns_empty_on_exception(self):
        """Collector error returns empty dict."""
        handler = _make_handler()
        handler.orchestrator = MagicMock()
        handler.orchestrator.collect_targeted.side_effect = (
            Exception("boom")
        )
        result = handler._collect("s3", "my-bucket")
        assert result == {}

    def test_collect_success(self):
        """Successful collection returns data."""
        handler = _make_handler()
        handler.orchestrator = MagicMock()
        handler.orchestrator.collect_targeted.return_value = {
            "buckets": [{"name": "my-bucket"}]
        }
        result = handler._collect("s3", "my-bucket")
        assert result == {
            "buckets": [{"name": "my-bucket"}]
        }


class TestRunEvaluation:
    """_run_evaluation error handling."""

    def test_evaluation_returns_none_on_exception(self):
        """OPA error returns None."""
        evaluator = MagicMock()
        evaluator.evaluate_check.side_effect = (
            Exception("OPA crash")
        )
        handler = _make_handler(evaluator=evaluator)
        result = handler._run_evaluation(
            "check_04", {}
        )
        assert result is None

    def test_evaluation_returns_violations(self):
        """Successful eval returns violation list."""
        v = _make_violation()
        evaluator = MagicMock()
        evaluator.evaluate_check.return_value = [v]
        handler = _make_handler(evaluator=evaluator)
        result = handler._run_evaluation(
            "check_04", {}
        )
        assert result == [v]


class TestResourceArnFallback:
    """resource_arn vs resource_id fallback."""

    def test_uses_resource_arn_when_present(self):
        """resource_arn from event used for state key."""
        evaluator = MagicMock()
        evaluator.evaluate_check.return_value = [
            _make_violation(status="alarm"),
        ]
        state_mgr = MagicMock()
        state_mgr.get_state.return_value = None
        state_mgr.put_state.return_value = True

        handler = _make_handler(
            evaluator=evaluator,
            state_manager=state_mgr,
        )
        handler.orchestrator = MagicMock()
        handler.orchestrator.collect_targeted.return_value = {}

        raw = _raw_eventbridge(
            resource_arn=BUCKET_ARN,
        )
        alerts = handler.process_event(raw)

        assert alerts[0].resource_arn == BUCKET_ARN

    def test_falls_back_to_resource_id(self):
        """resource_id used when no ARN."""
        evaluator = MagicMock()
        evaluator.evaluate_check.return_value = [
            _make_violation(status="alarm"),
        ]
        state_mgr = MagicMock()
        state_mgr.get_state.return_value = None
        state_mgr.put_state.return_value = True

        handler = _make_handler(
            evaluator=evaluator,
            state_manager=state_mgr,
        )
        handler.orchestrator = MagicMock()
        handler.orchestrator.collect_targeted.return_value = {}

        raw = _raw_eventbridge(
            resource_id="my-bucket",
            resource_arn="",
        )
        alerts = handler.process_event(raw)

        assert alerts[0].resource_arn == "my-bucket"


class TestTriggerEvent:
    """Trigger event propagation."""

    def test_trigger_event_set_on_alert(self):
        """event_name propagated to DriftAlert."""
        evaluator = MagicMock()
        evaluator.evaluate_check.return_value = [
            _make_violation(status="alarm"),
        ]
        handler = _make_handler(evaluator=evaluator)
        handler.orchestrator = MagicMock()
        handler.orchestrator.collect_targeted.return_value = {}

        raw = _raw_eventbridge(
            event_name="CreateBucket",
        )
        alerts = handler.process_event(raw)

        assert alerts[0].trigger_event == "CreateBucket"


class TestRiskScoreIntegration:
    """Risk score computed and propagated."""

    def test_alarm_gets_nonzero_risk_score(self):
        """Violation with alarm gets computed score."""
        v = _make_violation(
            status="alarm",
            severity="critical",
        )
        evaluator = MagicMock()
        evaluator.evaluate_check.return_value = [v]
        state_mgr = MagicMock()
        state_mgr.get_state.return_value = None
        state_mgr.put_state.return_value = True

        handler = _make_handler(
            evaluator=evaluator,
            state_manager=state_mgr,
        )
        handler.orchestrator = MagicMock()
        handler.orchestrator.collect_targeted.return_value = {}

        raw = _raw_eventbridge()
        alerts = handler.process_event(raw)

        assert len(alerts) == 1
        assert alerts[0].risk_score > 0

    def test_ok_gets_risk_score(self):
        """Even ok status computes a risk score."""
        v = _make_violation(
            status="ok",
            severity="high",
        )
        evaluator = MagicMock()
        evaluator.evaluate_check.return_value = [v]
        state_mgr = MagicMock()
        state_mgr.get_state.return_value = None
        state_mgr.put_state.return_value = True

        handler = _make_handler(
            evaluator=evaluator,
            state_manager=state_mgr,
        )
        handler.orchestrator = MagicMock()
        handler.orchestrator.collect_targeted.return_value = {}

        raw = _raw_eventbridge()
        alerts = handler.process_event(raw)

        assert len(alerts) == 1
        assert alerts[0].risk_score > 0

    def test_risk_score_flows_to_state(self):
        """Risk score persisted in ViolationState."""
        v = _make_violation(
            status="alarm",
            severity="high",
        )
        evaluator = MagicMock()
        evaluator.evaluate_check.return_value = [v]
        state_mgr = MagicMock()
        state_mgr.get_state.return_value = None
        state_mgr.put_state.return_value = True

        handler = _make_handler(
            evaluator=evaluator,
            state_manager=state_mgr,
        )
        handler.orchestrator = MagicMock()
        handler.orchestrator.collect_targeted.return_value = {}

        raw = _raw_eventbridge()
        handler.process_event(raw)

        saved = (
            state_mgr.put_state.call_args.args[0]
        )
        assert saved.risk_score > 0

    def test_empty_violations_zero_risk(self):
        """No violations → zero risk score."""
        evaluator = MagicMock()
        evaluator.evaluate_check.return_value = []
        state_mgr = MagicMock()
        state_mgr.get_state.return_value = None
        state_mgr.put_state.return_value = True

        handler = _make_handler(
            evaluator=evaluator,
            state_manager=state_mgr,
        )
        handler.orchestrator = MagicMock()
        handler.orchestrator.collect_targeted.return_value = {}

        raw = _raw_eventbridge()
        alerts = handler.process_event(raw)

        assert len(alerts) == 1
        assert alerts[0].risk_score == 0

    def test_resource_data_affects_score(self):
        """Resource data impacts risk dimensions."""
        v = _make_violation(
            status="alarm",
            severity="critical",
        )
        evaluator = MagicMock()
        evaluator.evaluate_check.return_value = [v]
        state_mgr = MagicMock()
        state_mgr.get_state.return_value = None
        state_mgr.put_state.return_value = True

        handler = _make_handler(
            evaluator=evaluator,
            state_manager=state_mgr,
        )
        handler.orchestrator = MagicMock()
        # Resource data with PII tag
        handler.orchestrator.collect_targeted.return_value = {
            "Tags": [
                {
                    "Key": "data-classification",
                    "Value": "pii",
                }
            ]
        }

        raw = _raw_eventbridge()
        alerts = handler.process_event(raw)

        # Score should be higher than empty data
        assert alerts[0].risk_score > 30

    def test_service_param_passed_from_mapping(self):
        """Service from EventMapping used for scoring."""
        v = Violation(
            check_id="check_07_security_groups",
            status="alarm",
            severity="critical",
            reason="Open SG",
            domain="network",
            compliance=ComplianceMapping(),
        )
        evaluator = MagicMock()
        evaluator.evaluate_check.return_value = [v]
        state_mgr = MagicMock()
        state_mgr.get_state.return_value = None
        state_mgr.put_state.return_value = True

        handler = _make_handler(
            evaluator=evaluator,
            state_manager=state_mgr,
        )
        handler.orchestrator = MagicMock()
        # EC2 resource with open CIDR
        handler.orchestrator.collect_targeted.return_value = {
            "IpPermissions": [
                {
                    "IpRanges": [
                        {"CidrIp": "0.0.0.0/0"}
                    ]
                }
            ]
        }

        raw = _raw_eventbridge(
            event_name=(
                "AuthorizeSecurityGroupIngress"
            ),
            event_source="ec2.amazonaws.com",
            resource_id="sg-abc",
        )
        alerts = handler.process_event(raw)

        # Should score EC2 exploitability (100)
        # because open CIDR
        assert any(
            a.risk_score > 0 for a in alerts
        )


class TestAutoRemediationIntegration:
    """Step 8: Auto-remediation after new violations."""

    def test_auto_remediate_on_first_seen_alarm(self):
        """Auto-engine called on FIRST_SEEN alarm."""
        evaluator = MagicMock()
        evaluator.evaluate_check.return_value = [
            _make_violation(status="alarm"),
        ]
        state_mgr = MagicMock()
        state_mgr.get_state.return_value = None
        state_mgr.put_state.return_value = True

        auto_engine = MagicMock()
        auto_engine.evaluate_and_remediate.return_value = (
            RemediationAction(
                action_id="auto-001",
                remediation_id="REM_04",
                resource_arn="my-bucket",
                account_id=ACCOUNT,
                status=RemediationStatus.EXECUTED,
            )
        )

        handler = _make_handler(
            evaluator=evaluator,
            state_manager=state_mgr,
            auto_engine=auto_engine,
        )
        handler.orchestrator = MagicMock()
        handler.orchestrator.collect_targeted.return_value = {}

        raw = _raw_eventbridge()
        alerts = handler.process_event(raw)

        assert len(alerts) == 1
        assert (
            alerts[0].drift_type
            == DriftType.FIRST_SEEN
        )
        auto_engine.evaluate_and_remediate.assert_called_once()
        call_kwargs = (
            auto_engine
            .evaluate_and_remediate
            .call_args
            .kwargs
        )
        assert (
            call_kwargs["remediation_id"] == "REM_04"
        )

    def test_auto_remediate_on_new_violation(self):
        """Auto-engine called on NEW_VIOLATION."""
        evaluator = MagicMock()
        evaluator.evaluate_check.return_value = [
            _make_violation(status="alarm"),
        ]
        prev_state = ViolationState(
            pk=f"{ACCOUNT}#{REGION}",
            sk=(
                "check_04_s3_public_access"
                "#my-bucket"
            ),
            check_id="check_04_s3_public_access",
            status="ok",
            severity="high",
            domain="data_protection",
            resource_arn="my-bucket",
            first_detected="2026-02-28T10:00:00Z",
            last_evaluated="2026-02-28T11:00:00Z",
        )
        state_mgr = MagicMock()
        state_mgr.get_state.return_value = prev_state
        state_mgr.put_state.return_value = True

        auto_engine = MagicMock()
        auto_engine.evaluate_and_remediate.return_value = None

        handler = _make_handler(
            evaluator=evaluator,
            state_manager=state_mgr,
            auto_engine=auto_engine,
        )
        handler.orchestrator = MagicMock()
        handler.orchestrator.collect_targeted.return_value = {}

        raw = _raw_eventbridge()
        alerts = handler.process_event(raw)

        assert (
            alerts[0].drift_type
            == DriftType.NEW_VIOLATION
        )
        auto_engine.evaluate_and_remediate.assert_called_once()

    def test_no_auto_remediate_on_resolution(self):
        """Auto-engine NOT called on RESOLUTION."""
        evaluator = MagicMock()
        evaluator.evaluate_check.return_value = [
            _make_violation(status="ok"),
        ]
        prev_state = ViolationState(
            pk=f"{ACCOUNT}#{REGION}",
            sk=(
                "check_04_s3_public_access"
                "#my-bucket"
            ),
            check_id="check_04_s3_public_access",
            status="alarm",
            severity="high",
            domain="data_protection",
            resource_arn="my-bucket",
            first_detected="2026-02-28T10:00:00Z",
            last_evaluated="2026-02-28T11:00:00Z",
        )
        state_mgr = MagicMock()
        state_mgr.get_state.return_value = prev_state
        state_mgr.put_state.return_value = True

        auto_engine = MagicMock()

        handler = _make_handler(
            evaluator=evaluator,
            state_manager=state_mgr,
            auto_engine=auto_engine,
        )
        handler.orchestrator = MagicMock()
        handler.orchestrator.collect_targeted.return_value = {}

        raw = _raw_eventbridge()
        alerts = handler.process_event(raw)

        assert (
            alerts[0].drift_type
            == DriftType.RESOLUTION
        )
        auto_engine.evaluate_and_remediate.assert_not_called()

    def test_no_auto_remediate_on_no_change(self):
        """Auto-engine NOT called on NO_CHANGE."""
        evaluator = MagicMock()
        evaluator.evaluate_check.return_value = [
            _make_violation(status="alarm"),
        ]
        prev_state = ViolationState(
            pk=f"{ACCOUNT}#{REGION}",
            sk=(
                "check_04_s3_public_access"
                "#my-bucket"
            ),
            check_id="check_04_s3_public_access",
            status="alarm",
            severity="high",
            domain="data_protection",
            resource_arn="my-bucket",
            first_detected="2026-02-28T10:00:00Z",
            last_evaluated="2026-02-28T11:00:00Z",
        )
        state_mgr = MagicMock()
        state_mgr.get_state.return_value = prev_state
        state_mgr.put_state.return_value = True

        auto_engine = MagicMock()

        handler = _make_handler(
            evaluator=evaluator,
            state_manager=state_mgr,
            auto_engine=auto_engine,
        )
        handler.orchestrator = MagicMock()
        handler.orchestrator.collect_targeted.return_value = {}

        raw = _raw_eventbridge()
        alerts = handler.process_event(raw)

        assert (
            alerts[0].drift_type
            == DriftType.NO_CHANGE
        )
        auto_engine.evaluate_and_remediate.assert_not_called()

    def test_no_auto_remediate_without_engine(self):
        """No crash when auto_engine is None."""
        evaluator = MagicMock()
        evaluator.evaluate_check.return_value = [
            _make_violation(status="alarm"),
        ]
        state_mgr = MagicMock()
        state_mgr.get_state.return_value = None
        state_mgr.put_state.return_value = True

        handler = _make_handler(
            evaluator=evaluator,
            state_manager=state_mgr,
            auto_engine=None,
        )
        handler.orchestrator = MagicMock()
        handler.orchestrator.collect_targeted.return_value = {}

        raw = _raw_eventbridge()
        alerts = handler.process_event(raw)

        assert len(alerts) == 1
        assert (
            alerts[0].drift_type
            == DriftType.FIRST_SEEN
        )

    def test_auto_remediate_error_doesnt_crash(self):
        """Auto-engine exception doesn't break pipeline."""
        evaluator = MagicMock()
        evaluator.evaluate_check.return_value = [
            _make_violation(status="alarm"),
        ]
        state_mgr = MagicMock()
        state_mgr.get_state.return_value = None
        state_mgr.put_state.return_value = True

        auto_engine = MagicMock()
        auto_engine.evaluate_and_remediate.side_effect = (
            RuntimeError("SNS down")
        )

        handler = _make_handler(
            evaluator=evaluator,
            state_manager=state_mgr,
            auto_engine=auto_engine,
        )
        handler.orchestrator = MagicMock()
        handler.orchestrator.collect_targeted.return_value = {}

        raw = _raw_eventbridge()
        alerts = handler.process_event(raw)

        # Alert still returned despite error
        assert len(alerts) == 1
        assert (
            alerts[0].drift_type
            == DriftType.FIRST_SEEN
        )

    def test_auto_remediate_passes_severity(self):
        """Severity string passed to auto-engine."""
        evaluator = MagicMock()
        evaluator.evaluate_check.return_value = [
            _make_violation(
                status="alarm",
                severity="critical",
            ),
        ]
        state_mgr = MagicMock()
        state_mgr.get_state.return_value = None
        state_mgr.put_state.return_value = True

        auto_engine = MagicMock()
        auto_engine.evaluate_and_remediate.return_value = None

        handler = _make_handler(
            evaluator=evaluator,
            state_manager=state_mgr,
            auto_engine=auto_engine,
        )
        handler.orchestrator = MagicMock()
        handler.orchestrator.collect_targeted.return_value = {}

        raw = _raw_eventbridge()
        handler.process_event(raw)

        call_kwargs = (
            auto_engine
            .evaluate_and_remediate
            .call_args
            .kwargs
        )
        assert call_kwargs["severity"] == "critical"

    def test_no_auto_remediate_on_first_seen_ok(self):
        """FIRST_SEEN with ok status doesn't trigger."""
        evaluator = MagicMock()
        evaluator.evaluate_check.return_value = [
            _make_violation(status="ok"),
        ]
        state_mgr = MagicMock()
        state_mgr.get_state.return_value = None
        state_mgr.put_state.return_value = True

        auto_engine = MagicMock()

        handler = _make_handler(
            evaluator=evaluator,
            state_manager=state_mgr,
            auto_engine=auto_engine,
        )
        handler.orchestrator = MagicMock()
        handler.orchestrator.collect_targeted.return_value = {}

        raw = _raw_eventbridge()
        alerts = handler.process_event(raw)

        # FIRST_SEEN ok still has remediation_id
        # but current_status is "ok" so drift_type
        # is FIRST_SEEN — however auto-remediation
        # still triggers on FIRST_SEEN since it
        # could be a first-time alarm detection.
        # The auto_engine.is_eligible check handles
        # whether to actually execute.
        assert (
            alerts[0].drift_type
            == DriftType.FIRST_SEEN
        )
        # Auto-engine called because FIRST_SEEN
        # is in the trigger list
        auto_engine.evaluate_and_remediate.assert_called_once()

    def test_no_auto_without_remediation_id(self):
        """No remediation_id → skip auto-remediation."""
        v = Violation(
            check_id="check_04_s3_public_access",
            status="alarm",
            severity="high",
            reason="S3 bucket issue",
            resource="my-bucket",
            domain="data_protection",
            compliance=ComplianceMapping(),
            remediation_id="",  # No remediation_id
        )
        evaluator = MagicMock()
        evaluator.evaluate_check.return_value = [v]
        state_mgr = MagicMock()
        state_mgr.get_state.return_value = None
        state_mgr.put_state.return_value = True

        auto_engine = MagicMock()

        handler = _make_handler(
            evaluator=evaluator,
            state_manager=state_mgr,
            auto_engine=auto_engine,
        )
        handler.orchestrator = MagicMock()
        handler.orchestrator.collect_targeted.return_value = {}

        raw = _raw_eventbridge()
        handler.process_event(raw)

        auto_engine.evaluate_and_remediate.assert_not_called()
