package aws.check_18_cloudwatch

import future.keywords.in

required_alarms := [
	"UnauthorizedAPICalls",
	"RootAccountUsage",
	"ConsoleSignInFailures",
	"IAMPolicyChanges",
	"CloudTrailChanges",
	"SecurityGroupChanges",
	"NACLChanges",
	"NetworkGatewayChanges",
	"RouteTableChanges",
	"VPCChanges",
]

violations contains result if {
	some required in required_alarms
	not alarm_exists(required)
	result := {
		"check_id": "CHECK_18",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"Missing CloudWatch alarm: %s",
			[required],
		),
		"resource": concat("", [
			"arn:aws:cloudwatch::", input.account_id,
			":alarm/", required,
		]),
		"domain": "logging",
		"compliance": {
			"cis_aws": ["4.1"],
			"nist_800_53": ["AU-6"],
		},
		"remediation_id": "REM_18",
	}
}

alarm_exists(name) if {
	some alarm in input.logging.cloudwatch_alarms
	alarm.alarm_name == name
}

error contains result if {
	not input.logging
	result := {
		"check_id": "CHECK_18",
		"status": "error",
		"severity": "medium",
		"reason": "Logging data missing from input — collector may have failed",
		"resource": "",
		"domain": "logging",
	}
}
