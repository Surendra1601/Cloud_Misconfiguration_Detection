package aws.check_12_aws_config_test

import data.aws.check_12_aws_config

test_alarm_no_recorders if {
	result := check_12_aws_config.violations with input as {
		"account_id": "123",
		"logging": {"config_recorders": []},
	}
	count(result) == 1
}

test_alarm_not_recording if {
	result := check_12_aws_config.violations with input as {
		"account_id": "123",
		"logging": {"config_recorders": [{
			"name": "default",
			"recording": false,
			"all_supported": true,
		}]},
	}
	count(result) > 0
}

test_compliant if {
	result := check_12_aws_config.compliant with input as {
		"account_id": "123",
		"logging": {"config_recorders": [{
			"name": "default",
			"recording": true,
			"all_supported": true,
		}]},
	}
	count(result) == 1
}
