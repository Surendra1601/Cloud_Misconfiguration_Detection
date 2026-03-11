package aws.check_13_guardduty

violations contains result if {
	count(input.logging.guardduty_detectors) == 0
	result := {
		"check_id": "CHECK_13",
		"status": "alarm",
		"severity": "high",
		"reason": "GuardDuty is not enabled",
		"resource": concat("", [
			"arn:aws:guardduty::", input.account_id,
			":no-detector",
		]),
		"domain": "detection",
		"compliance": {
			"cis_aws": ["4.15"],
			"nist_800_53": ["SI-4"],
		},
		"remediation_id": "REM_13",
	}
}

violations contains result if {
	some det in input.logging.guardduty_detectors
	det.status != "ENABLED"
	result := {
		"check_id": "CHECK_13",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"GuardDuty detector %s is not enabled",
			[det.detector_id],
		),
		"resource": concat("", [
			"arn:aws:guardduty::", input.account_id,
			":detector/", det.detector_id,
		]),
		"domain": "detection",
		"compliance": {
			"cis_aws": ["4.15"],
			"nist_800_53": ["SI-4"],
		},
		"remediation_id": "REM_13",
	}
}

compliant contains result if {
	some det in input.logging.guardduty_detectors
	det.status == "ENABLED"
	result := {
		"check_id": "CHECK_13",
		"status": "ok",
		"severity": "high",
		"reason": sprintf(
			"GuardDuty detector %s is enabled",
			[det.detector_id],
		),
		"resource": concat("", [
			"arn:aws:guardduty::", input.account_id,
			":detector/", det.detector_id,
		]),
		"domain": "detection",
	}
}

error contains result if {
	not input.ec2
	result := {
		"check_id": "CHECK_13",
		"status": "error",
		"severity": "high",
		"reason": "EC2 data missing from input — collector may have failed",
		"resource": "",
		"domain": "detection",
	}
}
