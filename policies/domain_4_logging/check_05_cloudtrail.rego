package aws.check_05_cloudtrail

violations contains result if {
	count(input.logging.cloudtrail_trails) == 0
	result := {
		"check_id": "CHECK_05",
		"status": "alarm",
		"severity": "critical",
		"reason": "No CloudTrail trails are configured",
		"resource": concat("", ["arn:aws:cloudtrail::", input.account_id, ":no-trails"]),
		"domain": "logging",
		"compliance": {
			"cis_aws": ["3.1"],
			"nist_800_53": ["AU-2", "AU-3"],
		},
		"remediation_id": "REM_05",
	}
}

violations contains result if {
	some trail in input.logging.cloudtrail_trails
	trail.is_logging == false
	result := {
		"check_id": "CHECK_05",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf(
			"CloudTrail %s is not logging",
			[trail.name],
		),
		"resource": trail.arn,
		"domain": "logging",
		"compliance": {
			"cis_aws": ["3.1"],
			"nist_800_53": ["AU-2"],
		},
		"remediation_id": "REM_05",
	}
}

violations contains result if {
	some trail in input.logging.cloudtrail_trails
	trail.is_multi_region == false
	result := {
		"check_id": "CHECK_05",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf(
			"CloudTrail %s is not multi-region",
			[trail.name],
		),
		"resource": trail.arn,
		"domain": "logging",
		"compliance": {
			"cis_aws": ["3.2"],
			"nist_800_53": ["AU-2"],
		},
		"remediation_id": "REM_05b",
	}
}

violations contains result if {
	some trail in input.logging.cloudtrail_trails
	trail.log_file_validation == false
	result := {
		"check_id": "CHECK_05",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf(
			"CloudTrail %s has no log file validation",
			[trail.name],
		),
		"resource": trail.arn,
		"domain": "logging",
		"compliance": {
			"cis_aws": ["3.4"],
			"nist_800_53": ["AU-3"],
		},
		"remediation_id": "REM_05c",
	}
}

compliant contains result if {
	some trail in input.logging.cloudtrail_trails
	trail.is_logging == true
	trail.is_multi_region == true
	trail.log_file_validation == true
	result := {
		"check_id": "CHECK_05",
		"status": "ok",
		"severity": "critical",
		"reason": sprintf(
			"CloudTrail %s is properly configured",
			[trail.name],
		),
		"resource": trail.arn,
		"domain": "logging",
	}
}

error contains result if {
	not input.logging
	result := {
		"check_id": "CHECK_05",
		"status": "error",
		"severity": "critical",
		"reason": "Logging data missing from input — collector may have failed",
		"resource": "",
		"domain": "logging",
	}
}
