package aws.check_16_secrets_manager_test

import data.aws.check_16_secrets_manager

test_alarm_no_rotation if {
	result := check_16_secrets_manager.violations with input as {"secrets_manager": {"secrets": [{
		"name": "db-pass",
		"arn": "arn:1",
		"rotation_enabled": false,
	}]}}
	count(result) == 1
}

test_compliant_rotation_enabled if {
	result := check_16_secrets_manager.compliant with input as {"secrets_manager": {"secrets": [{
		"name": "db-pass",
		"arn": "arn:2",
		"rotation_enabled": true,
	}]}}
	count(result) == 1
}
