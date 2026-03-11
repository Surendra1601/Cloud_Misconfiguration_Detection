import {
  render,
  screen,
  act,
} from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { AuthProvider } from "@/context/AuthContext";
import Sidebar from "../Sidebar";

function setUser(
  role: string,
  name: string = "testuser",
) {
  localStorage.setItem("auth_token", "t");
  localStorage.setItem(
    "auth_user",
    JSON.stringify({
      sub: "u1",
      email: `${name}@test.com`,
      name,
      role,
      groups: [role],
    }),
  );
}

function renderSidebar() {
  return render(
    <AuthProvider>
      <MemoryRouter>
        <Sidebar />
      </MemoryRouter>
    </AuthProvider>,
  );
}

describe("Sidebar", () => {
  it("renders CloudLine branding", () => {
    renderSidebar();
    expect(
      screen.getByText("CloudLine"),
    ).toBeInTheDocument();
    expect(
      screen.getByText("AWS Security"),
    ).toBeInTheDocument();
  });

  it("renders all nav links", () => {
    renderSidebar();
    expect(
      screen.getByText("Dashboard"),
    ).toBeInTheDocument();
    expect(
      screen.getByText("Violations"),
    ).toBeInTheDocument();
    expect(
      screen.getByText("Trends"),
    ).toBeInTheDocument();
    expect(
      screen.getByText("Remediation"),
    ).toBeInTheDocument();
    expect(
      screen.getByText("Executive"),
    ).toBeInTheDocument();
  });

  it("shows version", () => {
    renderSidebar();
    expect(
      screen.getByText("v0.1.0"),
    ).toBeInTheDocument();
  });

  it("shows user info when authenticated", () => {
    setUser("admin", "alice");
    renderSidebar();

    expect(
      screen.getByText("alice"),
    ).toBeInTheDocument();
    expect(
      screen.getByText("admin"),
    ).toBeInTheDocument();
  });

  it("shows sign out button", () => {
    setUser("operator");
    renderSidebar();

    expect(
      screen.getByLabelText("Sign out"),
    ).toBeInTheDocument();
  });

  it("logout clears user", () => {
    setUser("admin", "alice");
    renderSidebar();

    act(() =>
      screen.getByLabelText("Sign out").click(),
    );

    expect(
      screen.queryByText("alice"),
    ).not.toBeInTheDocument();
    expect(localStorage.getItem("auth_token")).toBeNull();
  });

  it("hides user section when not authenticated", () => {
    renderSidebar();
    expect(
      screen.queryByLabelText("Sign out"),
    ).not.toBeInTheDocument();
  });
});
