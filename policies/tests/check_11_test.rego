package aws.check_11_encryption_transit_test

import data.aws.check_11_encryption_transit

test_alarm_no_encryption if {
	result := check_11_encryption_transit.violations with input as {"s3": {"buckets": [{
		"name": "open",
		"arn": "arn:1",
		"encryption": {"enabled": false},
	}]}}
	count(result) == 1
}

test_compliant_encrypted if {
	result := check_11_encryption_transit.compliant with input as {"s3": {"buckets": [{
		"name": "secure",
		"arn": "arn:2",
		"encryption": {"enabled": true, "type": "AES256"},
	}]}}
	count(result) == 1
}
