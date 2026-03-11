package aws.check_09_rds_security_test

import data.aws.check_09_rds_security

test_alarm_publicly_accessible if {
	result := check_09_rds_security.violations with input as {"rds": {"db_instances": [{
		"db_instance_id": "db-1",
		"arn": "arn:1",
		"publicly_accessible": true,
		"storage_encrypted": true,
		"backup_retention_period": 7,
	}]}}
	count(result) > 0
}

test_alarm_unencrypted if {
	result := check_09_rds_security.violations with input as {"rds": {"db_instances": [{
		"db_instance_id": "db-2",
		"arn": "arn:2",
		"publicly_accessible": false,
		"storage_encrypted": false,
		"backup_retention_period": 7,
	}]}}
	count(result) > 0
}

test_compliant if {
	result := check_09_rds_security.compliant with input as {"rds": {"db_instances": [{
		"db_instance_id": "db-3",
		"arn": "arn:3",
		"publicly_accessible": false,
		"storage_encrypted": true,
		"backup_retention_period": 7,
	}]}}
	count(result) == 1
}
