package aws.check_19_access_analyzer

violations contains result if {
	count(input.iam.access_analyzer.analyzers) == 0
	result := {
		"check_id": "CHECK_19",
		"status": "alarm",
		"severity": "medium",
		"reason": "No IAM Access Analyzer is enabled",
		"resource": concat("", ["arn:aws:iam::", input.account_id, ":access-analyzer"]),
		"domain": "identity",
		"compliance": {
			"cis_aws": ["1.20"],
			"nist_800_53": ["AC-6"],
		},
		"remediation_id": "REM_19",
	}
}

compliant contains result if {
	count(input.iam.access_analyzer.analyzers) > 0
	result := {
		"check_id": "CHECK_19",
		"status": "ok",
		"severity": "medium",
		"reason": "IAM Access Analyzer is enabled",
		"resource": concat("", ["arn:aws:iam::", input.account_id, ":access-analyzer"]),
		"domain": "identity",
	}
}

error contains result if {
	not input.iam
	result := {
		"check_id": "CHECK_19",
		"status": "error",
		"severity": "medium",
		"reason": "IAM data missing from input — collector may have failed",
		"resource": "",
		"domain": "identity",
	}
}
