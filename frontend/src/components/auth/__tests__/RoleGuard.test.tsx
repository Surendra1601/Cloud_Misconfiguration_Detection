import { render, screen } from "@testing-library/react";
import { AuthProvider } from "@/context/AuthContext";
import RoleGuard from "../RoleGuard";

function setUser(role: string) {
  localStorage.setItem("auth_token", "t");
  localStorage.setItem(
    "auth_user",
    JSON.stringify({
      sub: "u1",
      email: "a@b.com",
      name: "a",
      role,
      groups: [role],
    }),
  );
}

function renderGuard(
  required: "viewer" | "operator" | "admin",
  fallback?: React.ReactNode,
) {
  return render(
    <AuthProvider>
      <RoleGuard required={required} fallback={fallback}>
        <div>Protected Content</div>
      </RoleGuard>
    </AuthProvider>,
  );
}

describe("RoleGuard", () => {
  it("shows content when role matches", () => {
    setUser("admin");
    renderGuard("admin");
    expect(
      screen.getByText("Protected Content"),
    ).toBeInTheDocument();
  });

  it("shows content when role exceeds requirement", () => {
    setUser("admin");
    renderGuard("viewer");
    expect(
      screen.getByText("Protected Content"),
    ).toBeInTheDocument();
  });

  it("hides content when role is insufficient", () => {
    setUser("viewer");
    renderGuard("admin");
    expect(
      screen.queryByText("Protected Content"),
    ).not.toBeInTheDocument();
    expect(
      screen.getByText(/insufficient permissions/i),
    ).toBeInTheDocument();
  });

  it("shows custom fallback when role is insufficient", () => {
    setUser("viewer");
    renderGuard(
      "operator",
      <div>Custom Fallback</div>,
    );
    expect(
      screen.getByText("Custom Fallback"),
    ).toBeInTheDocument();
  });

  it("shows default fallback with required role name", () => {
    setUser("viewer");
    renderGuard("operator");
    expect(
      screen.getByText("operator"),
    ).toBeInTheDocument();
  });

  it("hides content when not authenticated", () => {
    renderGuard("viewer");
    expect(
      screen.queryByText("Protected Content"),
    ).not.toBeInTheDocument();
  });
});
