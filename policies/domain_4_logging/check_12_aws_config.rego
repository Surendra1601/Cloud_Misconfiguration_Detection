package aws.check_12_aws_config

violations contains result if {
	count(input.logging.config_recorders) == 0
	result := {
		"check_id": "CHECK_12",
		"status": "alarm",
		"severity": "medium",
		"reason": "AWS Config recorder is not configured",
		"resource": concat("", ["arn:aws:config::", input.account_id, ":no-recorder"]),
		"domain": "logging",
		"compliance": {
			"cis_aws": ["3.5"],
			"nist_800_53": ["CM-3"],
		},
		"remediation_id": "REM_12",
	}
}

violations contains result if {
	some rec in input.logging.config_recorders
	rec.recording == false
	result := {
		"check_id": "CHECK_12",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"AWS Config recorder %s is not recording",
			[rec.name],
		),
		"resource": concat("", [
			"arn:aws:config::", input.account_id,
			":recorder/", rec.name,
		]),
		"domain": "logging",
		"compliance": {
			"cis_aws": ["3.5"],
			"nist_800_53": ["CM-3"],
		},
		"remediation_id": "REM_12",
	}
}

violations contains result if {
	some rec in input.logging.config_recorders
	rec.recording == true
	rec.all_supported == false
	result := {
		"check_id": "CHECK_12",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"AWS Config recorder %s is not recording all resource types",
			[rec.name],
		),
		"resource": concat("", [
			"arn:aws:config::", input.account_id,
			":recorder/", rec.name,
		]),
		"domain": "logging",
		"compliance": {
			"cis_aws": ["3.5"],
			"nist_800_53": ["CM-3"],
		},
		"remediation_id": "REM_12b",
	}
}

compliant contains result if {
	some rec in input.logging.config_recorders
	rec.recording == true
	rec.all_supported == true
	result := {
		"check_id": "CHECK_12",
		"status": "ok",
		"severity": "medium",
		"reason": sprintf(
			"AWS Config recorder %s is properly configured",
			[rec.name],
		),
		"resource": concat("", [
			"arn:aws:config::", input.account_id,
			":recorder/", rec.name,
		]),
		"domain": "logging",
	}
}

error contains result if {
	not input.logging
	result := {
		"check_id": "CHECK_12",
		"status": "error",
		"severity": "medium",
		"reason": "Logging data missing from input — collector may have failed",
		"resource": "",
		"domain": "logging",
	}
}
