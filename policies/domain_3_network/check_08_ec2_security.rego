package aws.check_08_ec2_security

violations contains result if {
	some inst in input.ec2.instances
	inst.metadata_options.http_tokens != "required"
	result := {
		"check_id": "CHECK_08",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"EC2 %s has IMDSv1 enabled (http_tokens != required)",
			[inst.instance_id],
		),
		"resource": inst.arn,
		"domain": "network",
		"compliance": {
			"cis_aws": ["5.6"],
			"nist_800_53": ["AC-4"],
		},
		"remediation_id": "REM_08",
	}
}

compliant contains result if {
	some inst in input.ec2.instances
	inst.metadata_options.http_tokens == "required"
	result := {
		"check_id": "CHECK_08",
		"status": "ok",
		"severity": "high",
		"reason": sprintf(
			"EC2 %s enforces IMDSv2",
			[inst.instance_id],
		),
		"resource": inst.arn,
		"domain": "network",
	}
}

error contains result if {
	not input.ec2
	result := {
		"check_id": "CHECK_08",
		"status": "error",
		"severity": "high",
		"reason": "EC2 data missing from input — collector may have failed",
		"resource": "",
		"domain": "network",
	}
}
