package aws.check_07_security_groups

_open_cidr(cidr) if cidr == "0.0.0.0/0"

_open_cidr(cidr) if cidr == "::/0"

violations contains result if {
	some sg in input.ec2.security_groups
	some rule in sg.ingress_rules
	rule.from_port <= 22
	rule.to_port >= 22
	_open_cidr(rule.cidr)
	result := {
		"check_id": "CHECK_07",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf(
			"%s allows SSH from %s",
			[sg.group_name, rule.cidr],
		),
		"resource": concat("", [sg.group_id]),
		"domain": "network",
		"compliance": {
			"cis_aws": ["5.2"],
			"nist_800_53": ["AC-4", "SC-7"],
			"pci_dss": ["1.3.1"],
		},
		"remediation_id": "REM_07",
	}
}

violations contains result if {
	some sg in input.ec2.security_groups
	some rule in sg.ingress_rules
	rule.from_port <= 3389
	rule.to_port >= 3389
	_open_cidr(rule.cidr)
	result := {
		"check_id": "CHECK_07",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf(
			"%s allows RDP from %s",
			[sg.group_name, rule.cidr],
		),
		"resource": concat("", [sg.group_id]),
		"domain": "network",
		"compliance": {
			"cis_aws": ["5.3"],
			"nist_800_53": ["AC-4", "SC-7"],
		},
		"remediation_id": "REM_07b",
	}
}

error contains result if {
	not input.ec2
	result := {
		"check_id": "CHECK_07",
		"status": "error",
		"severity": "critical",
		"reason": "EC2 data missing from input — collector may have failed",
		"resource": "",
		"domain": "network",
	}
}
