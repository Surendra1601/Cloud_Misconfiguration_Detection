import {
  useQuery,
  useMutation,
  useQueryClient,
} from "@tanstack/react-query";
import {
  getRemediations,
  getRemediation,
  executeRemediation,
  rollbackRemediation,
  getAuditTrail,
  getConfigs,
  saveConfig,
} from "@/api";
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

export function useRemediations() {
  return useQuery<RemediationsResponse>({
    queryKey: ["remediations"],
    queryFn: getRemediations,
  });
}

export function useRemediationDetail(
  id: string | null,
) {
  return useQuery<RemediationTemplate>({
    queryKey: ["remediation", id],
    queryFn: () => getRemediation(id!),
    enabled: !!id,
  });
}

export function useAuditTrail(params?: AuditParams) {
  return useQuery<AuditResponse>({
    queryKey: ["auditTrail", params],
    queryFn: () => getAuditTrail(params),
  });
}

export function useRemediationConfigs() {
  return useQuery<ConfigsResponse>({
    queryKey: ["remediationConfigs"],
    queryFn: getConfigs,
  });
}

export function useExecuteRemediation() {
  const qc = useQueryClient();
  return useMutation<
    RemediationActionResponse,
    unknown,
    { id: string; request: ExecuteRequest }
  >({
    mutationFn: ({ id, request }) =>
      executeRemediation(id, request),
    onSuccess: () => {
      qc.invalidateQueries({
        queryKey: ["auditTrail"],
      });
    },
  });
}

export function useRollbackRemediation() {
  const qc = useQueryClient();
  return useMutation<
    RollbackResponse,
    unknown,
    { id: string; request: RollbackRequest }
  >({
    mutationFn: ({ id, request }) =>
      rollbackRemediation(id, request),
    onSuccess: () => {
      qc.invalidateQueries({
        queryKey: ["auditTrail"],
      });
    },
  });
}

export function useSaveConfig() {
  const qc = useQueryClient();
  return useMutation<
    ConfigSaveResponse,
    unknown,
    ConfigRequest
  >({
    mutationFn: saveConfig,
    onSuccess: () => {
      qc.invalidateQueries({
        queryKey: ["remediationConfigs"],
      });
    },
  });
}
