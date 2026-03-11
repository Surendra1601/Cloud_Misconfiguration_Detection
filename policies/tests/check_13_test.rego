package aws.check_13_guardduty_test

import data.aws.check_13_guardduty

test_alarm_no_detectors if {
	result := check_13_guardduty.violations with input as {
		"account_id": "123",
		"logging": {"guardduty_detectors": []},
	}
	count(result) == 1
}

test_alarm_disabled_detector if {
	result := check_13_guardduty.violations with input as {
		"account_id": "123",
		"logging": {"guardduty_detectors": [{
			"detector_id": "det-1",
			"status": "DISABLED",
		}]},
	}
	count(result) > 0
}

test_compliant_enabled if {
	result := check_13_guardduty.compliant with input as {
		"account_id": "123",
		"logging": {"guardduty_detectors": [{
			"detector_id": "det-1",
			"status": "ENABLED",
		}]},
	}
	count(result) == 1
}
