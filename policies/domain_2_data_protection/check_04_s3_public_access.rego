package aws.check_04_s3_public_access

violations contains result if {
	some bucket in input.s3.buckets
	pab := bucket.public_access_block
	not all_blocked(pab)
	result := {
		"check_id": "CHECK_04",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf(
			"%s does not fully block public access",
			[bucket.name],
		),
		"resource": bucket.arn,
		"domain": "data_protection",
		"compliance": {
			"cis_aws": ["2.1.4"],
			"nist_800_53": ["AC-3", "AC-4"],
			"pci_dss": ["1.2.1"],
		},
		"remediation_id": "REM_04",
	}
}

compliant contains result if {
	some bucket in input.s3.buckets
	pab := bucket.public_access_block
	all_blocked(pab)
	result := {
		"check_id": "CHECK_04",
		"status": "ok",
		"severity": "critical",
		"reason": sprintf(
			"%s blocks all public access",
			[bucket.name],
		),
		"resource": bucket.arn,
		"domain": "data_protection",
	}
}

all_blocked(pab) if {
	pab.block_public_acls == true
	pab.block_public_policy == true
	pab.ignore_public_acls == true
	pab.restrict_public_buckets == true
}

error contains result if {
	not input.s3
	result := {
		"check_id": "CHECK_04",
		"status": "error",
		"severity": "critical",
		"reason": "S3 data missing from input — collector may have failed",
		"resource": "",
		"domain": "data_protection",
	}
}
