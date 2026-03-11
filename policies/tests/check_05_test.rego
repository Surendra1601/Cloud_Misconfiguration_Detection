package aws.check_05_cloudtrail_test

import data.aws.check_05_cloudtrail

test_alarm_no_trails if {
	result := check_05_cloudtrail.violations with input as {
		"account_id": "123",
		"logging": {"cloudtrail_trails": []},
	}
	count(result) == 1
}

test_alarm_not_logging if {
	result := check_05_cloudtrail.violations with input as {
		"account_id": "123",
		"logging": {"cloudtrail_trails": [{
			"name": "trail1",
			"arn": "arn:1",
			"is_logging": false,
			"is_multi_region": true,
			"log_file_validation": true,
		}]},
	}
	count(result) > 0
}

test_compliant_trail if {
	result := check_05_cloudtrail.compliant with input as {
		"account_id": "123",
		"logging": {"cloudtrail_trails": [{
			"name": "trail1",
			"arn": "arn:1",
			"is_logging": true,
			"is_multi_region": true,
			"log_file_validation": true,
		}]},
	}
	count(result) == 1
}
