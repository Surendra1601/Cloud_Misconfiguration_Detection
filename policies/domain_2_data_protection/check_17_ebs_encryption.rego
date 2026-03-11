package aws.check_17_ebs_encryption

violations contains result if {
	some vol in input.ec2.ebs_volumes
	vol.encrypted == false
	result := {
		"check_id": "CHECK_17",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"EBS volume %s is not encrypted",
			[vol.volume_id],
		),
		"resource": vol.arn,
		"domain": "data_protection",
		"compliance": {
			"cis_aws": ["2.2.1"],
			"nist_800_53": ["SC-28"],
			"pci_dss": ["3.4"],
			"hipaa": ["164.312(a)(2)(iv)"],
		},
		"remediation_id": "REM_17",
	}
}

compliant contains result if {
	some vol in input.ec2.ebs_volumes
	vol.encrypted == true
	result := {
		"check_id": "CHECK_17",
		"status": "ok",
		"severity": "high",
		"reason": sprintf(
			"EBS volume %s is encrypted",
			[vol.volume_id],
		),
		"resource": vol.arn,
		"domain": "data_protection",
	}
}

error contains result if {
	not input.ec2
	result := {
		"check_id": "CHECK_17",
		"status": "error",
		"severity": "high",
		"reason": "EC2 data missing from input — collector may have failed",
		"resource": "",
		"domain": "data_protection",
	}
}
