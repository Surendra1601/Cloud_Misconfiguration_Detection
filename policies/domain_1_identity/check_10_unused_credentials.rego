package aws.check_10_unused_credentials

violations contains result if {
	some user in input.iam.users
	user.last_activity_days_ago != null
	user.last_activity_days_ago > 90
	result := {
		"check_id": "CHECK_10",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"User %s inactive for %d days",
			[user.name, user.last_activity_days_ago],
		),
		"resource": user.arn,
		"domain": "identity",
		"compliance": {
			"cis_aws": ["1.12"],
			"nist_800_53": ["AC-2(3)"],
		},
		"remediation_id": "REM_10",
	}
}

violations contains result if {
	some user in input.iam.users
	some key in user.access_keys
	key.status == "Active"
	key.last_used_days_ago != null
	key.last_used_days_ago > 90
	result := {
		"check_id": "CHECK_10",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"Access key %s for user %s unused for %d days",
			[key.key_id, user.name, key.last_used_days_ago],
		),
		"resource": user.arn,
		"domain": "identity",
		"compliance": {
			"cis_aws": ["1.12"],
			"nist_800_53": ["AC-2(3)"],
		},
		"remediation_id": "REM_10b",
	}
}

error contains result if {
	not input.iam
	result := {
		"check_id": "CHECK_10",
		"status": "error",
		"severity": "medium",
		"reason": "IAM data missing from input — collector may have failed",
		"resource": "",
		"domain": "identity",
	}
}
