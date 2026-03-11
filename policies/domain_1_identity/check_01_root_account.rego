package aws.check_01_root_account

violations contains result if {
	summary := input.iam.account_summary
	summary.mfa_enabled == false
	result := {
		"check_id": "CHECK_01",
		"status": "alarm",
		"severity": "critical",
		"reason": "Root account does NOT have MFA enabled",
		"resource": concat("", ["arn:aws:iam::", input.account_id, ":root"]),
		"domain": "identity",
		"compliance": {
			"cis_aws": ["1.5"],
			"nist_800_53": ["IA-2(1)"],
			"pci_dss": ["8.3.1"],
		},
		"remediation_id": "REM_01",
	}
}

compliant contains result if {
	summary := input.iam.account_summary
	summary.mfa_enabled == true
	result := {
		"check_id": "CHECK_01",
		"status": "ok",
		"severity": "critical",
		"reason": "Root account has MFA enabled",
		"resource": concat("", ["arn:aws:iam::", input.account_id, ":root"]),
		"domain": "identity",
	}
}

error contains result if {
	not input.iam
	result := {
		"check_id": "CHECK_01",
		"status": "error",
		"severity": "critical",
		"reason": "IAM data missing from input — collector may have failed",
		"resource": "",
		"domain": "identity",
	}
}
