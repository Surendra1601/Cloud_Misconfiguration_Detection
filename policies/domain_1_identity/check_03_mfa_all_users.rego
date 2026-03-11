package aws.check_03_mfa_all_users

violations contains result if {
	some user in input.iam.users
	user.mfa_enabled == false
	result := {
		"check_id": "CHECK_03",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"IAM user %s does not have MFA enabled",
			[user.name],
		),
		"resource": user.arn,
		"domain": "identity",
		"compliance": {
			"cis_aws": ["1.10"],
			"nist_800_53": ["IA-2(1)"],
		},
		"remediation_id": "REM_03",
	}
}

compliant contains result if {
	some user in input.iam.users
	user.mfa_enabled == true
	result := {
		"check_id": "CHECK_03",
		"status": "ok",
		"severity": "high",
		"reason": sprintf(
			"IAM user %s has MFA enabled",
			[user.name],
		),
		"resource": user.arn,
		"domain": "identity",
	}
}

error contains result if {
	not input.iam
	result := {
		"check_id": "CHECK_03",
		"status": "error",
		"severity": "high",
		"reason": "IAM data missing from input — collector may have failed",
		"resource": "",
		"domain": "identity",
	}
}
