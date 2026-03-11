package aws.check_20_backup_recovery

violations contains result if {
	count(input.backup.plans) == 0
	result := {
		"check_id": "CHECK_20",
		"status": "alarm",
		"severity": "medium",
		"reason": "No AWS Backup plans configured",
		"resource": concat("", ["arn:aws:backup::", input.account_id, ":no-plans"]),
		"domain": "data_protection",
		"compliance": {
			"nist_800_53": ["CP-9"],
			"hipaa": ["164.308(a)(7)"],
		},
		"remediation_id": "REM_20",
	}
}

violations contains result if {
	some bucket in input.s3.buckets
	bucket.versioning == false
	result := {
		"check_id": "CHECK_20",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"S3 bucket %s does not have versioning enabled",
			[bucket.name],
		),
		"resource": bucket.arn,
		"domain": "data_protection",
		"compliance": {"nist_800_53": ["CP-9"]},
		"remediation_id": "REM_20b",
	}
}

compliant contains result if {
	count(input.backup.plans) > 0
	result := {
		"check_id": "CHECK_20",
		"status": "ok",
		"severity": "medium",
		"reason": "AWS Backup plans are configured",
		"resource": concat("", ["arn:aws:backup::", input.account_id, ":plans"]),
		"domain": "data_protection",
	}
}

error contains result if {
	not input.backup
	result := {
		"check_id": "CHECK_20",
		"status": "error",
		"severity": "medium",
		"reason": "Backup data missing from input — collector may have failed",
		"resource": "",
		"domain": "data_protection",
	}
}
