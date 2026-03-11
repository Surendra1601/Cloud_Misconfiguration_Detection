package aws.check_06_vpc_flow_logs_test

import data.aws.check_06_vpc_flow_logs

test_alarm_no_flow_logs if {
	result := check_06_vpc_flow_logs.violations with input as {"vpc": {
		"vpcs": [{"vpc_id": "vpc-1", "cidr_block": "10.0.0.0/16"}],
		"flow_logs": [],
	}}
	count(result) == 1
}

test_compliant_with_flow_logs if {
	result := check_06_vpc_flow_logs.compliant with input as {"vpc": {
		"vpcs": [{"vpc_id": "vpc-1", "cidr_block": "10.0.0.0/16"}],
		"flow_logs": [{"flow_log_id": "fl-1", "resource_id": "vpc-1"}],
	}}
	count(result) == 1
}
