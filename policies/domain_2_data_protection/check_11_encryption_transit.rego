package aws.check_11_encryption_transit

violations contains result if {
	some bucket in input.s3.buckets
	bucket.encryption.enabled == false
	result := {
		"check_id": "CHECK_11",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"S3 bucket %s does not have server-side encryption",
			[bucket.name],
		),
		"resource": bucket.arn,
		"domain": "data_protection",
		"compliance": {
			"nist_800_53": ["SC-8"],
			"pci_dss": ["4.1"],
		},
		"remediation_id": "REM_11",
	}
}

compliant contains result if {
	some bucket in input.s3.buckets
	bucket.encryption.enabled == true
	result := {
		"check_id": "CHECK_11",
		"status": "ok",
		"severity": "high",
		"reason": sprintf(
			"S3 bucket %s has encryption enabled",
			[bucket.name],
		),
		"resource": bucket.arn,
		"domain": "data_protection",
	}
}

error contains result if {
	not input.rds
	result := {
		"check_id": "CHECK_11",
		"status": "error",
		"severity": "high",
		"reason": "RDS data missing from input — collector may have failed",
		"resource": "",
		"domain": "data_protection",
	}
}
