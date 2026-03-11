package aws.check_07_security_groups_test

import data.aws.check_07_security_groups

test_alarm_ssh_open if {
	result := check_07_security_groups.violations with input as {"ec2": {"security_groups": [{
		"group_id": "sg-1",
		"group_name": "web-sg",
		"ingress_rules": [{
			"from_port": 22,
			"to_port": 22,
			"protocol": "tcp",
			"cidr": "0.0.0.0/0",
		}],
	}]}}
	count(result) == 1
}

test_alarm_rdp_open if {
	result := check_07_security_groups.violations with input as {"ec2": {"security_groups": [{
		"group_id": "sg-2",
		"group_name": "rdp-sg",
		"ingress_rules": [{
			"from_port": 3389,
			"to_port": 3389,
			"protocol": "tcp",
			"cidr": "0.0.0.0/0",
		}],
	}]}}
	count(result) == 1
}

test_no_violation_restricted_cidr if {
	result := check_07_security_groups.violations with input as {"ec2": {"security_groups": [{
		"group_id": "sg-3",
		"group_name": "safe-sg",
		"ingress_rules": [{
			"from_port": 22,
			"to_port": 22,
			"protocol": "tcp",
			"cidr": "10.0.0.0/8",
		}],
	}]}}
	count(result) == 0
}
