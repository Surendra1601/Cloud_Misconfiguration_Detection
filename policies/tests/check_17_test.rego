package aws.check_17_ebs_encryption_test

import data.aws.check_17_ebs_encryption

test_alarm_unencrypted if {
	result := check_17_ebs_encryption.violations with input as {"ec2": {"ebs_volumes": [{
		"volume_id": "vol-1",
		"arn": "arn:1",
		"encrypted": false,
	}]}}
	count(result) == 1
}

test_compliant_encrypted if {
	result := check_17_ebs_encryption.compliant with input as {"ec2": {"ebs_volumes": [{
		"volume_id": "vol-2",
		"arn": "arn:2",
		"encrypted": true,
	}]}}
	count(result) == 1
}
