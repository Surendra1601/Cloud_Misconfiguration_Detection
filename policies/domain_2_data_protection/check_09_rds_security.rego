package aws.check_09_rds_security

violations contains result if {
	some db in input.rds.db_instances
	db.publicly_accessible == true
	result := {
		"check_id": "CHECK_09",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"RDS instance %s is publicly accessible",
			[db.db_instance_id],
		),
		"resource": db.arn,
		"domain": "data_protection",
		"compliance": {
			"cis_aws": ["2.3"],
			"nist_800_53": ["SC-7"],
			"pci_dss": ["1.3.1"],
		},
		"remediation_id": "REM_09",
	}
}

violations contains result if {
	some db in input.rds.db_instances
	db.storage_encrypted == false
	result := {
		"check_id": "CHECK_09",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"RDS instance %s storage is not encrypted",
			[db.db_instance_id],
		),
		"resource": db.arn,
		"domain": "data_protection",
		"compliance": {
			"nist_800_53": ["SC-28"],
			"pci_dss": ["3.4"],
		},
		"remediation_id": "REM_09b",
	}
}

violations contains result if {
	some db in input.rds.db_instances
	db.backup_retention_period == 0
	result := {
		"check_id": "CHECK_09",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"RDS instance %s has no backup retention",
			[db.db_instance_id],
		),
		"resource": db.arn,
		"domain": "data_protection",
		"compliance": {"nist_800_53": ["CP-9"]},
		"remediation_id": "REM_09c",
	}
}

compliant contains result if {
	some db in input.rds.db_instances
	db.publicly_accessible == false
	db.storage_encrypted == true
	db.backup_retention_period > 0
	result := {
		"check_id": "CHECK_09",
		"status": "ok",
		"severity": "high",
		"reason": sprintf(
			"RDS instance %s meets security requirements",
			[db.db_instance_id],
		),
		"resource": db.arn,
		"domain": "data_protection",
	}
}

error contains result if {
	not input.rds
	result := {
		"check_id": "CHECK_09",
		"status": "error",
		"severity": "high",
		"reason": "RDS data missing from input — collector may have failed",
		"resource": "",
		"domain": "data_protection",
	}
}
