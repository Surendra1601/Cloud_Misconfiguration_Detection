export type Severity = "critical" | "high" | "medium" | "low";

export type ViolationStatus = "alarm" | "ok" | "error" | "skip";

export interface ComplianceMapping {
  cis_aws: string[];
  nist_800_53: string[];
  pci_dss: string[];
  hipaa: string[];
  soc2: string[];
}

export interface Violation {
  check_id: string;
  status: ViolationStatus;
  severity: Severity;
  reason: string;
  resource: string;
  domain: string;
  compliance: ComplianceMapping;
  remediation_id: string;
}
