import {
  render,
  screen,
  act,
} from "@testing-library/react";
import type { ReactNode } from "react";
import {
  QueryClient,
  QueryClientProvider,
} from "@tanstack/react-query";
import RemediationPage from "../RemediationPage";

const mockRemediations = {
  data: null as unknown,
  isLoading: false,
  error: null as unknown,
};
const mockDetail = {
  data: null as unknown,
  isLoading: false,
  error: null as unknown,
};

vi.mock("@/hooks", () => ({
  useRemediations: () => mockRemediations,
  useRemediationDetail: () => mockDetail,
  useViolations: () => ({
    data: [
      { check_id: "CHECK_01", status: "alarm" },
    ],
    isLoading: false,
    error: null,
  }),
  useExecuteRemediation: () => ({
    mutate: vi.fn(),
    isPending: false,
  }),
  useRollbackRemediation: () => ({
    mutate: vi.fn(),
    isPending: false,
  }),
  useAuditTrail: () => ({
    data: { entries: [] },
    isLoading: false,
    error: null,
  }),
  useRemediationConfigs: () => ({
    data: { configs: [] },
    isLoading: false,
    error: null,
  }),
  useSaveConfig: () => ({
    mutate: vi.fn(),
    isPending: false,
  }),
}));

function Wrapper({ children }: { children: ReactNode }) {
  const qc = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
    },
  });
  return (
    <QueryClientProvider client={qc}>
      {children}
    </QueryClientProvider>
  );
}

function renderPage() {
  return render(
    <Wrapper>
      <RemediationPage />
    </Wrapper>,
  );
}

describe("RemediationPage", () => {
  afterEach(() => {
    mockRemediations.data = null;
    mockRemediations.isLoading = false;
    mockRemediations.error = null;
    mockDetail.data = null;
  });

  it("shows heading", () => {
    renderPage();
    expect(
      screen.getByText("Remediation"),
    ).toBeInTheDocument();
  });

  it("shows tab bar", () => {
    renderPage();
    expect(
      screen.getByText("Suggestions"),
    ).toBeInTheDocument();
    expect(
      screen.getByText("Audit Trail"),
    ).toBeInTheDocument();
    expect(
      screen.getByText("Auto-Remediation"),
    ).toBeInTheDocument();
  });

  it("shows loading state", () => {
    mockRemediations.isLoading = true;
    const { container } = renderPage();
    expect(
      container.querySelector(".animate-pulse"),
    ).toBeTruthy();
  });

  it("shows error state", () => {
    mockRemediations.error = { message: "fail" };
    renderPage();
    expect(
      screen.getByText(/failed to load remediations/i),
    ).toBeInTheDocument();
  });

  it("switches to audit tab", () => {
    renderPage();
    act(() =>
      screen.getByText("Audit Trail").click(),
    );
    expect(
      screen.getByText("Remediation Audit Trail"),
    ).toBeInTheDocument();
  });

  it("switches to config tab", () => {
    renderPage();
    act(() =>
      screen.getByText("Auto-Remediation").click(),
    );
    expect(
      screen.getByText(
        "Auto-Remediation Configuration",
      ),
    ).toBeInTheDocument();
  });
});
