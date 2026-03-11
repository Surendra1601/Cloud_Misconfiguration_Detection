import { apiClient } from "./client";
import type {
  RemediationsResponse,
  RemediationTemplate,
  ExecuteRequest,
  RemediationActionResponse,
  RollbackRequest,
  RollbackResponse,
  AuditResponse,
  AuditParams,
  ConfigsResponse,
  ConfigRequest,
  ConfigSaveResponse,
} from "@/types";

export async function getRemediations(): Promise<RemediationsResponse> {
  const { data } =
    await apiClient.get<RemediationsResponse>(
      "/v1/remediation",
    );
  return data;
}

export async function getRemediation(
  id: string,
): Promise<RemediationTemplate> {
  const { data } =
    await apiClient.get<RemediationTemplate>(
      `/v1/remediation/${id}`,
    );
  return data;
}

export async function executeRemediation(
  id: string,
  request: ExecuteRequest,
): Promise<RemediationActionResponse> {
  const { data } =
    await apiClient.post<RemediationActionResponse>(
      `/v1/remediation/${id}/execute`,
      request,
    );
  return data;
}

export async function rollbackRemediation(
  id: string,
  request: RollbackRequest,
): Promise<RollbackResponse> {
  const { data } =
    await apiClient.post<RollbackResponse>(
      `/v1/remediation/${id}/rollback`,
      request,
    );
  return data;
}

export async function getAuditTrail(
  params?: AuditParams,
): Promise<AuditResponse> {
  const { data } = await apiClient.get<AuditResponse>(
    "/v1/remediation/audit",
    { params },
  );
  return data;
}

export async function getConfigs(): Promise<ConfigsResponse> {
  const { data } = await apiClient.get<ConfigsResponse>(
    "/v1/remediation/config",
  );
  return data;
}

export async function saveConfig(
  request: ConfigRequest,
): Promise<ConfigSaveResponse> {
  const { data } =
    await apiClient.put<ConfigSaveResponse>(
      "/v1/remediation/config",
      request,
    );
  return data;
}
