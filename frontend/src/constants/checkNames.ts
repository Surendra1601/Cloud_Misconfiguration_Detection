/**
 * Human-readable names for each check ID.
 * Used across violations, remediation, and
 * executive summary pages.
 */
const CHECK_NAMES: Record<string, string> = {
  CHECK_01: "Root Account MFA Not Enabled",
  CHECK_02: "Weak IAM Password Policy",
  CHECK_03: "IAM User MFA Not Enabled",
  CHECK_04: "S3 Public Access Not Blocked",
  CHECK_05: "CloudTrail Logging Disabled",
  CHECK_06: "VPC Flow Logs Disabled",
  CHECK_07: "Open SSH/RDP Access in Security Group",
  CHECK_08: "EC2 IMDSv2 Not Enforced",
  CHECK_09: "Insecure RDS Configuration",
  CHECK_10: "Unused IAM Credentials Active",
  CHECK_11: "Encryption in Transit Disabled",
  CHECK_12: "AWS Config Not Recording",
  CHECK_13: "GuardDuty Not Enabled",
  CHECK_14: "Insecure Lambda Configuration",
  CHECK_15: "Overly Permissive Network ACL",
  CHECK_16: "Secrets Not in Secrets Manager",
  CHECK_17: "EBS Encryption Disabled",
  CHECK_18: "CloudWatch Alarms Not Configured",
  CHECK_19: "IAM Access Analyzer Disabled",
  CHECK_20: "AWS Backup Not Configured",
  CHECK_CROSS_01: "Capital One Attack Pattern",
};

export function getCheckName(checkId: string): string {
  return CHECK_NAMES[checkId] ?? checkId;
}

export default CHECK_NAMES;
