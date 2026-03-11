package aws.check_16_secrets_manager

violations contains result if {
	some secret in input.secrets_manager.secrets
	secret.rotation_enabled == false
	result := {
		"check_id": "CHECK_16",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"Secret %s does not have rotation enabled",
			[secret.name],
		),
		"resource": secret.arn,
		"domain": "data_protection",
		"compliance": {
			"cis_aws": ["2.4"],
			"nist_800_53": ["IA-5"],
		},
		"remediation_id": "REM_16",
	}
}

compliant contains result if {
	some secret in input.secrets_manager.secrets
	secret.rotation_enabled == true
	result := {
		"check_id": "CHECK_16",
		"status": "ok",
		"severity": "medium",
		"reason": sprintf(
			"Secret %s has rotation enabled",
			[secret.name],
		),
		"resource": secret.arn,
		"domain": "data_protection",
	}
}

error contains result if {
	not input.secrets_manager
	result := {
		"check_id": "CHECK_16",
		"status": "error",
		"severity": "high",
		"reason": "Secrets Manager data missing from input — collector may have failed",
		"resource": "",
		"domain": "data_protection",
	}
}
