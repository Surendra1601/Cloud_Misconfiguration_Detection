package aws.check_03_mfa_all_users_test

import data.aws.check_03_mfa_all_users

test_alarm_user_without_mfa if {
	result := check_03_mfa_all_users.violations with input as {"iam": {"users": [{"name": "alice", "arn": "arn:aws:iam::123:user/alice", "mfa_enabled": false}]}}
	count(result) == 1
}

test_ok_user_with_mfa if {
	result := check_03_mfa_all_users.compliant with input as {"iam": {"users": [{"name": "bob", "arn": "arn:aws:iam::123:user/bob", "mfa_enabled": true}]}}
	count(result) == 1
}

test_mixed_users if {
	violations := check_03_mfa_all_users.violations with input as {"iam": {"users": [
		{"name": "alice", "arn": "arn:1", "mfa_enabled": false},
		{"name": "bob", "arn": "arn:2", "mfa_enabled": true},
	]}}
	count(violations) == 1
}
