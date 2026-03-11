import { renderHook, waitFor, act } from "@testing-library/react";
import type { ReactNode } from "react";
import {
  QueryClient,
  QueryClientProvider,
} from "@tanstack/react-query";
import {
  useRemediations,
  useRemediationDetail,
  useAuditTrail,
  useRemediationConfigs,
  useExecuteRemediation,
  useRollbackRemediation,
  useSaveConfig,
} from "../useRemediation";

vi.mock("@/api", () => ({
  getRemediations: vi.fn().mockResolvedValue({
    templates: [
      { id: "REM_01", title: "Fix S3 public" },
    ],
  }),
  getRemediation: vi.fn().mockResolvedValue({
    id: "REM_01",
    title: "Fix S3 public access",
    tier: 1,
  }),
  getAuditTrail: vi.fn().mockResolvedValue({
    entries: [{ action_id: "a1", status: "success" }],
    count: 1,
  }),
  getConfigs: vi.fn().mockResolvedValue({
    configs: [
      { check_id: "CHECK_01", enabled: true },
    ],
  }),
  executeRemediation: vi.fn().mockResolvedValue({
    action_id: "act-1",
    status: "success",
    rollback_available_until: "2026-01-02T00:00:00Z",
  }),
  rollbackRemediation: vi.fn().mockResolvedValue({
    status: "rolled_back",
    message: "Rollback successful",
  }),
  saveConfig: vi.fn().mockResolvedValue({
    status: "saved",
  }),
}));

function createWrapper() {
  const qc = new QueryClient({
    defaultOptions: {
      queries: { retry: false, gcTime: 0 },
    },
  });
  return function Wrapper({
    children,
  }: {
    children: ReactNode;
  }) {
    return (
      <QueryClientProvider client={qc}>
        {children}
      </QueryClientProvider>
    );
  };
}

describe("useRemediations", () => {
  it("fetches remediation templates", async () => {
    const { result } = renderHook(
      () => useRemediations(),
      { wrapper: createWrapper() },
    );

    await waitFor(() =>
      expect(result.current.isSuccess).toBe(true),
    );
    expect(
      result.current.data?.templates,
    ).toHaveLength(1);
  });
});

describe("useRemediationDetail", () => {
  it("fetches detail when id provided", async () => {
    const { result } = renderHook(
      () => useRemediationDetail("REM_01"),
      { wrapper: createWrapper() },
    );

    await waitFor(() =>
      expect(result.current.isSuccess).toBe(true),
    );
    expect(result.current.data?.id).toBe("REM_01");
  });

  it("does not fetch when id is null", () => {
    const { result } = renderHook(
      () => useRemediationDetail(null),
      { wrapper: createWrapper() },
    );

    expect(result.current.isFetching).toBe(false);
  });
});

describe("useAuditTrail", () => {
  it("fetches audit entries", async () => {
    const { result } = renderHook(
      () => useAuditTrail(),
      { wrapper: createWrapper() },
    );

    await waitFor(() =>
      expect(result.current.isSuccess).toBe(true),
    );
    expect(
      result.current.data?.entries,
    ).toHaveLength(1);
  });
});

describe("useRemediationConfigs", () => {
  it("fetches config list", async () => {
    const { result } = renderHook(
      () => useRemediationConfigs(),
      { wrapper: createWrapper() },
    );

    await waitFor(() =>
      expect(result.current.isSuccess).toBe(true),
    );
    expect(
      result.current.data?.configs,
    ).toHaveLength(1);
  });
});

describe("useExecuteRemediation", () => {
  it("executes remediation mutation", async () => {
    const { result } = renderHook(
      () => useExecuteRemediation(),
      { wrapper: createWrapper() },
    );

    act(() => {
      result.current.mutate({
        id: "REM_01",
        request: {
          resource_arn: "arn:aws:s3:::bucket",
          confirm: true,
        },
      });
    });

    await waitFor(() =>
      expect(result.current.isSuccess).toBe(true),
    );
    expect(result.current.data?.action_id).toBe(
      "act-1",
    );
    expect(result.current.data?.status).toBe("success");
  });
});

describe("useRollbackRemediation", () => {
  it("executes rollback mutation", async () => {
    const { result } = renderHook(
      () => useRollbackRemediation(),
      { wrapper: createWrapper() },
    );

    act(() => {
      result.current.mutate({
        id: "REM_01",
        request: { action_id: "act-1" },
      });
    });

    await waitFor(() =>
      expect(result.current.isSuccess).toBe(true),
    );
    expect(result.current.data?.status).toBe(
      "rolled_back",
    );
  });
});

describe("useSaveConfig", () => {
  it("saves config mutation", async () => {
    const { result } = renderHook(
      () => useSaveConfig(),
      { wrapper: createWrapper() },
    );

    act(() => {
      result.current.mutate({
        check_id: "CHECK_01",
        enabled: true,
      });
    });

    await waitFor(() =>
      expect(result.current.isSuccess).toBe(true),
    );
    expect(result.current.data?.status).toBe("saved");
  });
});
