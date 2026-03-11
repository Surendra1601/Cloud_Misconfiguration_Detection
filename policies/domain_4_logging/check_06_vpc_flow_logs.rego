package aws.check_06_vpc_flow_logs

import future.keywords.in

violations contains result if {
	some vpc in input.vpc.vpcs
	not has_flow_log(vpc.vpc_id)
	result := {
		"check_id": "CHECK_06",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"VPC %s does not have flow logs enabled",
			[vpc.vpc_id],
		),
		"resource": vpc.vpc_id,
		"domain": "logging",
		"compliance": {
			"cis_aws": ["3.9"],
			"nist_800_53": ["AU-12"],
			"pci_dss": ["10.1"],
		},
		"remediation_id": "REM_06",
	}
}

compliant contains result if {
	some vpc in input.vpc.vpcs
	has_flow_log(vpc.vpc_id)
	result := {
		"check_id": "CHECK_06",
		"status": "ok",
		"severity": "high",
		"reason": sprintf(
			"VPC %s has flow logs enabled",
			[vpc.vpc_id],
		),
		"resource": vpc.vpc_id,
		"domain": "logging",
	}
}

has_flow_log(vpc_id) if {
	some fl in input.vpc.flow_logs
	fl.resource_id == vpc_id
}

error contains result if {
	not input.vpc
	result := {
		"check_id": "CHECK_06",
		"status": "error",
		"severity": "high",
		"reason": "VPC data missing from input — collector may have failed",
		"resource": "",
		"domain": "logging",
	}
}
