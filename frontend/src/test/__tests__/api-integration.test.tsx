/**
 * MSW Integration Tests — verify API client + hooks
 * against realistic mock server responses.
 */
import {
  renderHook,
  waitFor,
  render,
  screen,
} from "@testing-library/react";
import { http, HttpResponse } from "msw";
import type { ReactNode } from "react";
import {
  QueryClient,
  QueryClientProvider,
} from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { AuthProvider } from "@/context/AuthContext";
import { AlertProvider } from "@/context/AlertContext";
import { server } from "../msw/server";
import {
  mockCompliance,
  mockViolations,
  mockRiskSummary,
  mockRemediations,
  mockAudit,
  mockConfigs,
} from "../msw/handlers";

// API functions (direct imports, no mocking)
import { getHealth } from "@/api/health";
import { getComplianceScore } from "@/api/compliance";
import { getViolations } from "@/api/violations";
import { getDriftAlerts } from "@/api/drift";
import {
  getRiskSummary,
  getRiskScores,
} from "@/api/risk";
import {
  getRemediations,
  getRemediation,
  executeRemediation,
  rollbackRemediation,
  getAuditTrail,
  getConfigs,
  saveConfig,
} from "@/api/remediation";
import { triggerScan } from "@/api/scans";

// Hooks
import { useCompliance } from "@/hooks/useCompliance";
import { useViolations } from "@/hooks/useViolations";
import { useRiskSummary } from "@/hooks/useRiskSummary";
import {
  useRemediations,
  useAuditTrail,
  useRemediationConfigs,
} from "@/hooks/useRemediation";

// Pages
import DashboardPage from "@/pages/DashboardPage";

beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

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
        <AuthProvider>
          <AlertProvider>
            <MemoryRouter>{children}</MemoryRouter>
          </AlertProvider>
        </AuthProvider>
      </QueryClientProvider>
    );
  };
}

// ---- API Client Integration Tests ----

describe("API client integration (MSW)", () => {
  it("GET /health returns service info", async () => {
    const data = await getHealth();
    expect(data.status).toBe("ok");
    expect(data.service).toBe("cloudline");
  });

  it("GET /v1/compliance/score returns scores", async () => {
    const data = await getComplianceScore();
    expect(data.score_percent).toBe(80);
    expect(data.total_checks).toBe(20);
  });

  it("GET /v1/violations returns violations", async () => {
    const data = await getViolations();
    expect(data).toHaveLength(2);
    expect(data[0].check_id).toBe("CHECK_01");
  });

  it("GET /v1/violations with filters", async () => {
    const data = await getViolations({
      severity: "critical",
    });
    expect(data).toHaveLength(2);
  });

  it("GET /v1/drift/alerts returns alerts", async () => {
    const data = await getDriftAlerts();
    expect(data.alerts).toHaveLength(1);
    expect(data.alerts[0].type).toBe("new_violation");
  });

  it("GET /v1/risk/summary returns summary", async () => {
    const data = await getRiskSummary();
    expect(data.total_scored).toBe(10);
    expect(data.by_category.critical).toBe(2);
  });

  it("GET /v1/risk/scores returns scores", async () => {
    const data = await getRiskScores();
    expect(data.scores).toHaveLength(1);
    expect(data.scores[0].risk_score).toBe(92);
  });

  it("GET /v1/remediation returns templates", async () => {
    const data = await getRemediations();
    expect(data.remediations).toHaveLength(1);
    expect(data.remediations[0].remediation_id).toBe(
      "REM_01",
    );
  });

  it("GET /v1/remediation/:id returns detail", async () => {
    const data = await getRemediation("REM_01");
    expect(data.remediation_id).toBe("REM_01");
    expect(data.title).toBe("Block S3 Public Access");
  });

  it("POST /v1/remediation/:id/execute", async () => {
    const data = await executeRemediation("REM_01", {
      resource_arn: "arn:aws:s3:::test",
      confirm: true,
    });
    expect(data.status).toBe("success");
    expect(data.action_id).toBe("act-002");
  });

  it("POST /v1/remediation/:id/rollback", async () => {
    const data = await rollbackRemediation("REM_01", {
      action_id: "act-001",
    });
    expect(data.status).toBe("rolled_back");
  });

  it("GET /v1/remediation/audit", async () => {
    const data = await getAuditTrail();
    expect(data.entries).toHaveLength(1);
    expect(data.entries[0].action_id).toBe("act-001");
  });

  it("GET /v1/remediation/config", async () => {
    const data = await getConfigs();
    expect(data.configs).toHaveLength(1);
    expect(data.configs[0].check_id).toBe("CHECK_04");
  });

  it("PUT /v1/remediation/config", async () => {
    const data = await saveConfig({
      check_id: "CHECK_04",
      enabled: false,
    });
    expect(data.status).toBe("saved");
  });

  it("POST /v1/scans triggers scan", async () => {
    const data = await triggerScan();
    expect(data.account_id).toBe("123456789012");
  });
});

// ---- Error Handling ----

describe("API error handling (MSW)", () => {
  it("handles 500 server error", async () => {
    server.use(
      http.get("/api/v1/compliance/score", () =>
        HttpResponse.json(
          { detail: "Internal error" },
          { status: 500 },
        ),
      ),
    );

    await expect(
      getComplianceScore(),
    ).rejects.toMatchObject({
      status: 500,
      message: "Internal error",
    });
  });

  it("handles network error", async () => {
    server.use(
      http.get("/api/health", () =>
        HttpResponse.error(),
      ),
    );

    await expect(getHealth()).rejects.toBeDefined();
  });

  it("handles 401 unauthorized", async () => {
    server.use(
      http.get("/api/v1/violations", () =>
        HttpResponse.json(
          { detail: "Unauthorized" },
          { status: 401 },
        ),
      ),
    );

    await expect(
      getViolations(),
    ).rejects.toMatchObject({
      status: 401,
    });
  });
});

// ---- Hook Integration Tests ----

describe("Hook integration (MSW)", () => {
  it("useCompliance fetches real data", async () => {
    const { result } = renderHook(
      () => useCompliance(),
      { wrapper: createWrapper() },
    );

    await waitFor(() =>
      expect(result.current.isSuccess).toBe(true),
    );
    expect(result.current.data?.score_percent).toBe(
      mockCompliance.score_percent,
    );
  });

  it("useViolations fetches real data", async () => {
    const { result } = renderHook(
      () => useViolations(),
      { wrapper: createWrapper() },
    );

    await waitFor(() =>
      expect(result.current.isSuccess).toBe(true),
    );
    expect(result.current.data).toHaveLength(
      mockViolations.length,
    );
  });

  it("useRiskSummary fetches real data", async () => {
    const { result } = renderHook(
      () => useRiskSummary(),
      { wrapper: createWrapper() },
    );

    await waitFor(() =>
      expect(result.current.isSuccess).toBe(true),
    );
    expect(result.current.data?.total_scored).toBe(
      mockRiskSummary.total_scored,
    );
  });

  it("useRemediations fetches real data", async () => {
    const { result } = renderHook(
      () => useRemediations(),
      { wrapper: createWrapper() },
    );

    await waitFor(() =>
      expect(result.current.isSuccess).toBe(true),
    );
    expect(
      result.current.data?.remediations,
    ).toHaveLength(
      mockRemediations.remediations.length,
    );
  });

  it("useAuditTrail fetches real data", async () => {
    const { result } = renderHook(
      () => useAuditTrail(),
      { wrapper: createWrapper() },
    );

    await waitFor(() =>
      expect(result.current.isSuccess).toBe(true),
    );
    expect(
      result.current.data?.entries,
    ).toHaveLength(mockAudit.entries.length);
  });

  it("useRemediationConfigs fetches real data", async () => {
    const { result } = renderHook(
      () => useRemediationConfigs(),
      { wrapper: createWrapper() },
    );

    await waitFor(() =>
      expect(result.current.isSuccess).toBe(true),
    );
    expect(
      result.current.data?.configs,
    ).toHaveLength(mockConfigs.configs.length);
  });

  it("hook shows error on server failure", async () => {
    server.use(
      http.get("/api/v1/compliance/score", () =>
        HttpResponse.json(
          { detail: "fail" },
          { status: 500 },
        ),
      ),
    );

    const { result } = renderHook(
      () => useCompliance(),
      { wrapper: createWrapper() },
    );

    await waitFor(() =>
      expect(result.current.isError).toBe(true),
    );
  });
});

// ---- Page Integration Tests ----

describe("Page integration (MSW)", () => {
  it("DashboardPage loads compliance data", async () => {
    render(<DashboardPage />, {
      wrapper: createWrapper(),
    });

    await waitFor(() => {
      expect(
        screen.getAllByText(/80/).length,
      ).toBeGreaterThanOrEqual(1);
    });
  });

  it("DashboardPage shows risk cards", async () => {
    render(<DashboardPage />, {
      wrapper: createWrapper(),
    });

    await waitFor(() => {
      expect(
        screen.getAllByText(/Critical/i).length,
      ).toBeGreaterThanOrEqual(1);
    });
  });
});
