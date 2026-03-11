export interface ComplianceReference {
  framework: string;
  control_id: string;
  title: string;
}

export interface RemediationTemplate {
  remediation_id: string;
  title: string;
  domain: string;
  severity: string;
  check_id: string;
  console_steps: string[];
  cli_command: string;
  cli_example: string;
  terraform_snippet: string;
  references: ComplianceReference[];
  estimated_fix_time_minutes: number;
  risk_reduction: string;
  rollback_difficulty: string;
}

export interface RemediationsResponse {
  remediations: RemediationTemplate[];
  total: number;
}

export interface ExecuteRequest {
  resource_arn: string;
  account_id?: string;
  confirm?: boolean;
}

export interface RemediationActionResponse {
  action_id: string;
  status: string;
  remediation_id: string;
  resource_arn: string;
  rollback_available_until: string;
  error_message: string;
}

export interface RollbackRequest {
  action_id: string;
  account_id?: string;
}

export interface RollbackResponse {
  status: string;
  message: string;
}

export interface AuditEntry {
  action_id: string;
  remediation_id: string;
  check_id: string;
  resource_arn: string;
  action_taken: string;
  tier: string;
  initiated_by: string;
  status: string;
  rollback_deadline: string;
  created_at: string;
}

export interface AuditResponse {
  entries: AuditEntry[];
  total: number;
}

export interface AuditParams {
  remediation_id?: string;
  status?: string;
  limit?: number;
}

export interface AutoRemediationConfig {
  account_id: string;
  check_id: string;
  enabled: boolean;
  rollback_window_minutes: number;
  notify_on_action: boolean;
  approved_by: string;
  approved_at: string;
}

export interface ConfigsResponse {
  configs: AutoRemediationConfig[];
  total: number;
}

export interface ConfigRequest {
  account_id?: string;
  check_id: string;
  enabled?: boolean;
  rollback_window_minutes?: number;
  notify_on_action?: boolean;
  approved_by?: string;
}

export interface ConfigSaveResponse {
  status: string;
  account_id: string;
  check_id: string;
  enabled: boolean;
}
