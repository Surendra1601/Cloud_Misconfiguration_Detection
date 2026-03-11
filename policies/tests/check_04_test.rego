package aws.check_04_s3_public_access_test

import data.aws.check_04_s3_public_access

test_compliant_bucket if {
	result := check_04_s3_public_access.compliant with input as {"s3": {"buckets": [{
		"name": "secure",
		"arn": "arn:aws:s3:::secure",
		"public_access_block": {
			"block_public_acls": true,
			"block_public_policy": true,
			"ignore_public_acls": true,
			"restrict_public_buckets": true,
		},
	}]}}
	count(result) == 1
}

test_violation_bucket if {
	result := check_04_s3_public_access.violations with input as {"s3": {"buckets": [{
		"name": "open",
		"arn": "arn:aws:s3:::open",
		"public_access_block": {
			"block_public_acls": false,
			"block_public_policy": false,
			"ignore_public_acls": false,
			"restrict_public_buckets": false,
		},
	}]}}
	count(result) == 1
}

test_partial_block_is_violation if {
	result := check_04_s3_public_access.violations with input as {"s3": {"buckets": [{
		"name": "partial",
		"arn": "arn:aws:s3:::partial",
		"public_access_block": {
			"block_public_acls": true,
			"block_public_policy": true,
			"ignore_public_acls": false,
			"restrict_public_buckets": true,
		},
	}]}}
	count(result) == 1
}
