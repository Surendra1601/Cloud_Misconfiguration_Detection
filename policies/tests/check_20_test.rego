package aws.check_20_backup_recovery_test

import data.aws.check_20_backup_recovery

test_alarm_no_backup_plans if {
	result := check_20_backup_recovery.violations with input as {
		"account_id": "123",
		"backup": {"plans": []},
		"s3": {"buckets": []},
	}
	count(result) == 1
}

test_alarm_no_versioning if {
	result := check_20_backup_recovery.violations with input as {
		"account_id": "123",
		"backup": {"plans": [{"plan_id": "p1"}]},
		"s3": {"buckets": [{
			"name": "mybucket",
			"arn": "arn:1",
			"versioning": false,
		}]},
	}
	count(result) == 1
}

test_compliant if {
	result := check_20_backup_recovery.compliant with input as {
		"account_id": "123",
		"backup": {"plans": [{"plan_id": "p1"}]},
		"s3": {"buckets": [{
			"name": "mybucket",
			"arn": "arn:2",
			"versioning": true,
		}]},
	}
	count(result) == 1
}
