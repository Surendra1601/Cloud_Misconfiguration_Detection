package aws.check_19_access_analyzer_test

import data.aws.check_19_access_analyzer

test_alarm_no_analyzer if {
	result := check_19_access_analyzer.violations with input as {
		"account_id": "123",
		"iam": {"access_analyzer": {"analyzers": []}},
	}
	count(result) == 1
}

test_compliant_analyzer_exists if {
	result := check_19_access_analyzer.compliant with input as {
		"account_id": "123",
		"iam": {"access_analyzer": {"analyzers": [{"name": "default", "status": "ACTIVE"}]}},
	}
	count(result) == 1
}
