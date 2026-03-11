import { render, waitFor } from "@testing-library/react";
import App from "../App";

// Mock all pages to avoid deep dependency chains
vi.mock("@/pages", () => ({
  DashboardPage: () => <div>Dashboard</div>,
  ViolationsPage: () => <div>Violations</div>,
  TrendsPage: () => <div>Trends</div>,
  ExecutiveSummaryPage: () => <div>Executive</div>,
  RemediationPage: () => <div>Remediation</div>,
  PoliciesPage: () => <div>Policies</div>,
  LoginPage: () => <div data-testid="login">Login Page</div>,
}));

vi.mock("@/components/auth", () => ({
  ProtectedRoute: ({
    children,
  }: {
    children: React.ReactNode;
  }) => {
    const token = localStorage.getItem("auth_token");
    if (!token) {
      return <div data-testid="login">Login Page</div>;
    }
    return <>{children}</>;
  },
}));

vi.mock("@/components/layout", () => ({
  Layout: () => <div data-testid="layout">Layout</div>,
}));

describe("App", () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it("renders without crashing", async () => {
    render(<App />);

    await waitFor(() => {
      expect(
        document.body.querySelector("div"),
      ).toBeTruthy();
    });
  });

  it("renders app with providers", async () => {
    localStorage.setItem("auth_token", "test");
    localStorage.setItem(
      "auth_user",
      JSON.stringify({
        sub: "u1",
        email: "t@t.com",
        name: "test",
        role: "admin",
        groups: [],
      }),
    );

    render(<App />);

    await waitFor(() => {
      expect(
        document.body.querySelector("div"),
      ).toBeTruthy();
    });
  });
});
