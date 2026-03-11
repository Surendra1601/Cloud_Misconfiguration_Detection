package aws.check_02_password_policy

violations contains result if {
	pp := input.iam.password_policy
	pp.minimum_length < 14
	result := {
		"check_id": "CHECK_02",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"Password minimum length is %d, should be >= 14",
			[pp.minimum_length],
		),
		"resource": concat("", ["arn:aws:iam::", input.account_id, ":password-policy"]),
		"domain": "identity",
		"compliance": {
			"cis_aws": ["1.8"],
			"nist_800_53": ["IA-5"],
		},
		"remediation_id": "REM_02",
	}
}

violations contains result if {
	pp := input.iam.password_policy
	pp.require_symbols == false
	result := {
		"check_id": "CHECK_02",
		"status": "alarm",
		"severity": "high",
		"reason": "Password policy does not require symbols",
		"resource": concat("", ["arn:aws:iam::", input.account_id, ":password-policy"]),
		"domain": "identity",
		"compliance": {
			"cis_aws": ["1.9"],
			"nist_800_53": ["IA-5"],
		},
		"remediation_id": "REM_02",
	}
}

violations contains result if {
	pp := input.iam.password_policy
	pp.password_reuse_prevention < 24
	result := {
		"check_id": "CHECK_02",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"Password reuse prevention is %d, should be >= 24",
			[pp.password_reuse_prevention],
		),
		"resource": concat("", ["arn:aws:iam::", input.account_id, ":password-policy"]),
		"domain": "identity",
		"compliance": {
			"cis_aws": ["1.10"],
			"nist_800_53": ["IA-5"],
		},
		"remediation_id": "REM_02",
	}
}

violations contains result if {
	pp := input.iam.password_policy
	pp.max_age_days == 0
	result := {
		"check_id": "CHECK_02",
		"status": "alarm",
		"severity": "high",
		"reason": "Password policy has no max age set",
		"resource": concat("", ["arn:aws:iam::", input.account_id, ":password-policy"]),
		"domain": "identity",
		"compliance": {
			"cis_aws": ["1.11"],
			"nist_800_53": ["IA-5"],
		},
		"remediation_id": "REM_02",
	}
}

compliant contains result if {
	pp := input.iam.password_policy
	pp.minimum_length >= 14
	pp.require_symbols == true
	pp.require_numbers == true
	pp.require_uppercase == true
	pp.require_lowercase == true
	pp.password_reuse_prevention >= 24
	pp.max_age_days > 0
	result := {
		"check_id": "CHECK_02",
		"status": "ok",
		"severity": "high",
		"reason": "Password policy meets all requirements",
		"resource": concat("", ["arn:aws:iam::", input.account_id, ":password-policy"]),
		"domain": "identity",
	}
}

error contains result if {
	not input.iam
	result := {
		"check_id": "CHECK_02",
		"status": "error",
		"severity": "high",
		"reason": "IAM data missing from input — collector may have failed",
		"resource": "",
		"domain": "identity",
	}
}
