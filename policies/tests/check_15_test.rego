package aws.check_15_nacls_test

import data.aws.check_15_nacls

test_alarm_permissive_inbound if {
	result := check_15_nacls.violations with input as {"vpc": {"nacls": [{
		"nacl_id": "acl-1",
		"entries": [{
			"egress": false,
			"rule_action": "allow",
			"protocol": "-1",
			"cidr_block": "0.0.0.0/0",
			"rule_number": 100,
		}],
	}]}}
	count(result) == 1
}

test_no_alarm_egress_rule if {
	result := check_15_nacls.violations with input as {"vpc": {"nacls": [{
		"nacl_id": "acl-2",
		"entries": [{
			"egress": true,
			"rule_action": "allow",
			"protocol": "-1",
			"cidr_block": "0.0.0.0/0",
			"rule_number": 100,
		}],
	}]}}
	count(result) == 0
}

test_no_alarm_default_rule if {
	result := check_15_nacls.violations with input as {"vpc": {"nacls": [{
		"nacl_id": "acl-3",
		"entries": [{
			"egress": false,
			"rule_action": "allow",
			"protocol": "-1",
			"cidr_block": "0.0.0.0/0",
			"rule_number": 32767,
		}],
	}]}}
	count(result) == 0
}
