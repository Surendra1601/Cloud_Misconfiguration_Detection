package aws.check_01_root_account_test

import data.aws.check_01_root_account

test_alarm_no_mfa if {
	result := check_01_root_account.violations with input as {
		"account_id": "123456789012",
		"iam": {"account_summary": {"mfa_enabled": false}},
	}
	count(result) == 1
}

test_ok_with_mfa if {
	result := check_01_root_account.compliant with input as {
		"account_id": "123456789012",
		"iam": {"account_summary": {"mfa_enabled": true}},
	}
	count(result) == 1
}

test_no_violations_when_mfa_enabled if {
	result := check_01_root_account.violations with input as {
		"account_id": "123456789012",
		"iam": {"account_summary": {"mfa_enabled": true}},
	}
	count(result) == 0
}
