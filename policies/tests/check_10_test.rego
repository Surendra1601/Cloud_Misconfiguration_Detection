package aws.check_10_unused_credentials_test

import data.aws.check_10_unused_credentials

test_alarm_inactive_user if {
	result := check_10_unused_credentials.violations with input as {"iam": {"users": [{
		"name": "old-user",
		"arn": "arn:1",
		"last_activity_days_ago": 120,
		"access_keys": [],
	}]}}
	count(result) == 1
}

test_alarm_unused_key if {
	result := check_10_unused_credentials.violations with input as {"iam": {"users": [{
		"name": "user1",
		"arn": "arn:1",
		"last_activity_days_ago": 10,
		"access_keys": [{
			"key_id": "AKIA1",
			"status": "Active",
			"last_used_days_ago": 100,
		}],
	}]}}
	count(result) == 1
}

test_no_violation_active_user if {
	result := check_10_unused_credentials.violations with input as {"iam": {"users": [{
		"name": "active",
		"arn": "arn:1",
		"last_activity_days_ago": 5,
		"access_keys": [{
			"key_id": "AKIA2",
			"status": "Active",
			"last_used_days_ago": 3,
		}],
	}]}}
	count(result) == 0
}
