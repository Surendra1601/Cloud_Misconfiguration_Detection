package aws.check_18_cloudwatch_test

import data.aws.check_18_cloudwatch

test_alarm_missing_all if {
	result := check_18_cloudwatch.violations with input as {
		"account_id": "123",
		"logging": {"cloudwatch_alarms": []},
	}
	count(result) == 10
}

test_alarm_missing_one if {
	result := check_18_cloudwatch.violations with input as {
		"account_id": "123",
		"logging": {"cloudwatch_alarms": [
			{"alarm_name": "UnauthorizedAPICalls"},
			{"alarm_name": "RootAccountUsage"},
			{"alarm_name": "ConsoleSignInFailures"},
			{"alarm_name": "IAMPolicyChanges"},
			{"alarm_name": "CloudTrailChanges"},
			{"alarm_name": "SecurityGroupChanges"},
			{"alarm_name": "NACLChanges"},
			{"alarm_name": "NetworkGatewayChanges"},
			{"alarm_name": "RouteTableChanges"},
		]},
	}
	count(result) == 1
}

test_no_alarm_all_present if {
	result := check_18_cloudwatch.violations with input as {
		"account_id": "123",
		"logging": {"cloudwatch_alarms": [
			{"alarm_name": "UnauthorizedAPICalls"},
			{"alarm_name": "RootAccountUsage"},
			{"alarm_name": "ConsoleSignInFailures"},
			{"alarm_name": "IAMPolicyChanges"},
			{"alarm_name": "CloudTrailChanges"},
			{"alarm_name": "SecurityGroupChanges"},
			{"alarm_name": "NACLChanges"},
			{"alarm_name": "NetworkGatewayChanges"},
			{"alarm_name": "RouteTableChanges"},
			{"alarm_name": "VPCChanges"},
		]},
	}
	count(result) == 0
}
