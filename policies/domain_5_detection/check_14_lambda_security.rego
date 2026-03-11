package aws.check_14_lambda_security

violations contains result if {
	some fn in input.lambda_functions.functions
	fn.tracing_config != "Active"
	result := {
		"check_id": "CHECK_14",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"Lambda %s does not have X-Ray tracing enabled",
			[fn.function_name],
		),
		"resource": fn.arn,
		"domain": "detection",
		"compliance": {"nist_800_53": ["AC-6"]},
		"remediation_id": "REM_14",
	}
}

violations contains result if {
	some fn in input.lambda_functions.functions
	fn.environment_encryption == false
	result := {
		"check_id": "CHECK_14",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"Lambda %s does not encrypt environment variables with KMS",
			[fn.function_name],
		),
		"resource": fn.arn,
		"domain": "detection",
		"compliance": {"nist_800_53": ["SC-28"]},
		"remediation_id": "REM_14b",
	}
}

compliant contains result if {
	some fn in input.lambda_functions.functions
	fn.tracing_config == "Active"
	fn.environment_encryption == true
	result := {
		"check_id": "CHECK_14",
		"status": "ok",
		"severity": "medium",
		"reason": sprintf(
			"Lambda %s meets security requirements",
			[fn.function_name],
		),
		"resource": fn.arn,
		"domain": "detection",
	}
}

error contains result if {
	not input.lambda
	result := {
		"check_id": "CHECK_14",
		"status": "error",
		"severity": "medium",
		"reason": "Lambda data missing from input — collector may have failed",
		"resource": "",
		"domain": "serverless",
	}
}
