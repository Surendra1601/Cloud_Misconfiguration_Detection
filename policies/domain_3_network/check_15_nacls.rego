package aws.check_15_nacls

_open_cidr(cidr) if cidr == "0.0.0.0/0"

_open_cidr(cidr) if cidr == "::/0"

violations contains result if {
	some nacl in input.vpc.nacls
	some entry in nacl.entries
	entry.egress == false
	entry.rule_action == "allow"
	entry.protocol == "-1"
	_open_cidr(entry.cidr_block)
	entry.rule_number != 32767
	result := {
		"check_id": "CHECK_15",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"NACL %s has overly permissive inbound rule allowing all traffic from %s",
			[nacl.nacl_id, entry.cidr_block],
		),
		"resource": nacl.nacl_id,
		"domain": "network",
		"compliance": {
			"nist_800_53": ["AC-4", "SC-7"],
		},
		"remediation_id": "REM_15",
	}
}

error contains result if {
	not input.vpc
	result := {
		"check_id": "CHECK_15",
		"status": "error",
		"severity": "medium",
		"reason": "VPC data missing from input — collector may have failed",
		"resource": "",
		"domain": "network",
	}
}
