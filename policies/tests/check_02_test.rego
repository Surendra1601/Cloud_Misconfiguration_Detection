package aws.check_02_password_policy_test

import data.aws.check_02_password_policy

test_alarm_short_password if {
	result := check_02_password_policy.violations with input as {
		"account_id": "123",
		"iam": {"password_policy": {
			"minimum_length": 8,
			"require_symbols": true,
			"require_numbers": true,
			"require_uppercase": true,
			"require_lowercase": true,
			"max_age_days": 90,
			"password_reuse_prevention": 24,
		}},
	}
	count(result) > 0
}

test_alarm_no_symbols if {
	result := check_02_password_policy.violations with input as {
		"account_id": "123",
		"iam": {"password_policy": {
			"minimum_length": 14,
			"require_symbols": false,
			"require_numbers": true,
			"require_uppercase": true,
			"require_lowercase": true,
			"max_age_days": 90,
			"password_reuse_prevention": 24,
		}},
	}
	count(result) > 0
}

test_compliant_policy if {
	result := check_02_password_policy.compliant with input as {
		"account_id": "123",
		"iam": {"password_policy": {
			"minimum_length": 14,
			"require_symbols": true,
			"require_numbers": true,
			"require_uppercase": true,
			"require_lowercase": true,
			"max_age_days": 90,
			"password_reuse_prevention": 24,
		}},
	}
	count(result) == 1
}
