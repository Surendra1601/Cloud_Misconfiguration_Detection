# CloudLine Policy Writing Guide

How to add a new OPA/Rego security check to CloudLine.

## Overview

Each security check consists of 4 parts:

1. **Rego policy** — the detection logic
2. **Rego test** — unit tests for the policy
3. **Event mapping** — which CloudTrail events trigger re-evaluation
4. **Remediation template** — how to fix the issue

## Step 1: Write the Rego Policy

Create a new file in `policies/`:

```rego
# policies/check_21_example.rego
package aws.check_21_example

import rego.v1

# METADATA
# title: Example check description
# description: Ensures the resource is configured securely
# severity: high
# domain: data_protection

default allow := false

allow if {
    input.resource.secure_setting == true
}

violation contains result if {
    not allow
    result := {
        "check_id": "CHECK_21",
        "status": "alarm",
        "severity": "high",
        "reason": "Resource is not configured securely",
        "resource": input.resource.arn,
        "domain": "data_protection",
        "remediation_id": "REM_21",
        "compliance": {
            "cis_aws": ["x.x.x"],
            "nist_800_53": ["XX-X"],
            "pci_dss": [],
            "hipaa": [],
            "soc2": [],
        },
    }
}
```

### Conventions

- Package name: `aws.check_NN_description`
- Always include `check_id`, `status`, `severity`, `reason`, `resource`, `domain`
- Map to at least one compliance framework
- Use `input.resource` for the resource data

## Step 2: Write Tests

Create `policies/tests/check_21_example_test.rego`:

```rego
package aws.check_21_example_test

import rego.v1

import data.aws.check_21_example

test_secure_resource_allowed if {
    count(check_21_example.violation) == 0 with input as {
        "resource": {
            "arn": "arn:aws:service:::resource",
            "secure_setting": true,
        },
    }
}

test_insecure_resource_violation if {
    results := check_21_example.violation with input as {
        "resource": {
            "arn": "arn:aws:service:::resource",
            "secure_setting": false,
        },
    }
    count(results) == 1
    some result in results
    result.check_id == "CHECK_21"
    result.severity == "high"
}
```

Run tests:

```bash
opa test policies/ -v
opa fmt -w policies/  # auto-format
```

## Step 3: Add Event Mapping

Edit `backend/app/pipeline/models.py` to add CloudTrail
events that should trigger this check:

```python
EVENT_POLICY_MAP: dict[str, list[str]] = {
    # ... existing mappings ...
    "NewApiCall": ["check_21_example"],
}
```

This maps the CloudTrail `eventName` to the Rego
package(s) that should be re-evaluated when that event
fires.

## Step 4: Add Remediation Template

Create `backend/app/pipeline/remediation/templates/REM_21.json`:

```json
{
  "remediation_id": "REM_21",
  "check_id": "CHECK_21",
  "title": "Fix example resource",
  "domain": "data_protection",
  "severity": "high",
  "tier": 1,
  "console_steps": [
    "Go to the AWS Console",
    "Navigate to the service",
    "Update the setting"
  ],
  "cli_command": "aws service update-resource",
  "cli_example": "aws service update-resource --id xxx --secure true",
  "terraform_snippet": "resource \"aws_example\" \"main\" {\n  secure_setting = true\n}",
  "estimated_fix_time_minutes": 5,
  "risk_reduction": "High",
  "rollback_difficulty": "Easy",
  "references": [
    {
      "framework": "CIS AWS",
      "control_id": "x.x.x",
      "title": "Example control"
    }
  ]
}
```

### Tier Levels

| Tier | Type | Description |
|------|------|-------------|
| 1 | Suggestion | Console steps + CLI + Terraform (all checks) |
| 2 | One-Click | Automated boto3 execution (selected checks) |
| 3 | Auto | Runs automatically on new violations (configurable) |

To add Tier 2 (one-click) support, implement an executor
in `backend/app/pipeline/remediation/one_click.py` and a
rollback handler in `rollback.py`.

## Step 5: Add Risk Scoring (Optional)

The risk scorer uses 5 dimensions automatically:

1. **Severity** — from the policy metadata
2. **Exploitability** — service-specific (add to `risk_scorer.py`)
3. **Blast radius** — based on resource connectivity
4. **Data sensitivity** — from resource tags
5. **Compliance impact** — from mapped frameworks

To customize exploitability for a new service, add a case
to `_compute_exploitability()` in `risk_scorer.py`.

## Checklist

- [ ] Rego policy in `policies/check_NN_name.rego`
- [ ] Rego tests in `policies/tests/check_NN_name_test.rego`
- [ ] `opa test policies/ -v` passes
- [ ] `opa fmt --diff policies/` clean
- [ ] Event mapping in `EVENT_POLICY_MAP`
- [ ] Remediation template `REM_NN.json`
- [ ] Backend tests updated if needed
- [ ] PR with description of what the check detects

## Existing Checks Reference

| ID | Domain | Severity | Description |
|----|--------|----------|-------------|
| CHECK_01 | data_protection | critical | S3 public access |
| CHECK_02 | data_protection | high | S3 encryption |
| CHECK_03 | data_protection | medium | S3 bucket policy |
| CHECK_04 | logging | critical | CloudTrail disabled |
| CHECK_05 | logging | high | CloudTrail log validation |
| CHECK_06 | logging | medium | CloudTrail encryption |
| CHECK_07 | network | critical | Security group SSH open |
| CHECK_08 | network | high | Security group RDP open |
| CHECK_09 | network | medium | Default security group |
| CHECK_10 | identity_access | critical | IAM root access keys |
| CHECK_11 | identity_access | high | IAM MFA |
| CHECK_12 | identity_access | high | IAM password policy |
| CHECK_13 | identity_access | medium | IAM unused keys |
| CHECK_14 | data_protection | high | RDS encryption |
| CHECK_15 | data_protection | high | RDS public access |
| CHECK_16 | data_protection | medium | RDS multi-AZ |
| CHECK_17 | network | high | EC2 IMDSv2 |
| CHECK_18 | data_protection | high | EBS encryption |
| CHECK_19 | detection | critical | GuardDuty disabled |
| CHECK_20 | detection | high | Lambda public access |
