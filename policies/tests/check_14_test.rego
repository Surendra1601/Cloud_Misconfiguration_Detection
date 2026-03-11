package aws.check_14_lambda_security_test

import data.aws.check_14_lambda_security

test_alarm_no_tracing if {
	result := check_14_lambda_security.violations with input as {"lambda_functions": {"functions": [{
		"function_name": "fn1",
		"arn": "arn:1",
		"tracing_config": "PassThrough",
		"environment_encryption": true,
	}]}}
	count(result) == 1
}

test_alarm_no_env_encryption if {
	result := check_14_lambda_security.violations with input as {"lambda_functions": {"functions": [{
		"function_name": "fn2",
		"arn": "arn:2",
		"tracing_config": "Active",
		"environment_encryption": false,
	}]}}
	count(result) == 1
}

test_compliant if {
	result := check_14_lambda_security.compliant with input as {"lambda_functions": {"functions": [{
		"function_name": "fn3",
		"arn": "arn:3",
		"tracing_config": "Active",
		"environment_encryption": true,
	}]}}
	count(result) == 1
}
