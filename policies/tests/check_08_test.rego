package aws.check_08_ec2_security_test

import data.aws.check_08_ec2_security

test_alarm_imdsv1 if {
	result := check_08_ec2_security.violations with input as {"ec2": {"instances": [{
		"instance_id": "i-1",
		"arn": "arn:1",
		"metadata_options": {"http_tokens": "optional"},
	}]}}
	count(result) == 1
}

test_compliant_imdsv2 if {
	result := check_08_ec2_security.compliant with input as {"ec2": {"instances": [{
		"instance_id": "i-2",
		"arn": "arn:2",
		"metadata_options": {"http_tokens": "required"},
	}]}}
	count(result) == 1
}
