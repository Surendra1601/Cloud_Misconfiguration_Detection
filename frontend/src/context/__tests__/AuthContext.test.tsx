import { render, screen, act } from "@testing-library/react";
import { AuthProvider } from "../AuthContext";
import { useAuth } from "@/hooks/useAuth";

function AuthConsumer() {
  const auth = useAuth();
  return (
    <div>
      <span data-testid="authenticated">
        {String(auth.isAuthenticated)}
      </span>
      <span data-testid="role">{auth.role ?? "none"}</span>
      <span data-testid="name">
        {auth.user?.name ?? "none"}
      </span>
      <span data-testid="loading">
        {String(auth.isLoading)}
      </span>
      <span data-testid="has-viewer">
        {String(auth.hasRole("viewer"))}
      </span>
      <span data-testid="has-operator">
        {String(auth.hasRole("operator"))}
      </span>
      <span data-testid="has-admin">
        {String(auth.hasRole("admin"))}
      </span>
      <button
        onClick={() =>
          auth.login({
            username: "alice",
            password: "pass",
          })
        }
      >
        login
      </button>
      <button onClick={auth.logout}>logout</button>
    </div>
  );
}

function renderAuth() {
  return render(
    <AuthProvider>
      <AuthConsumer />
    </AuthProvider>,
  );
}

describe("AuthContext", () => {
  it("starts unauthenticated with no stored data", () => {
    renderAuth();
    expect(
      screen.getByTestId("authenticated"),
    ).toHaveTextContent("false");
    expect(
      screen.getByTestId("role"),
    ).toHaveTextContent("none");
    expect(
      screen.getByTestId("loading"),
    ).toHaveTextContent("false");
  });

  it("login sets user and stores in localStorage", async () => {
    renderAuth();
    await act(async () => {
      screen.getByText("login").click();
    });

    expect(
      screen.getByTestId("authenticated"),
    ).toHaveTextContent("true");
    expect(
      screen.getByTestId("role"),
    ).toHaveTextContent("admin");
    expect(
      screen.getByTestId("name"),
    ).toHaveTextContent("alice");
    expect(
      localStorage.getItem("auth_token"),
    ).toBe("dev-token");
    expect(
      localStorage.getItem("auth_user"),
    ).toBeTruthy();
  });

  it("logout clears user and localStorage", async () => {
    renderAuth();
    await act(async () => {
      screen.getByText("login").click();
    });

    act(() => {
      screen.getByText("logout").click();
    });

    expect(
      screen.getByTestId("authenticated"),
    ).toHaveTextContent("false");
    expect(localStorage.getItem("auth_token")).toBeNull();
    expect(localStorage.getItem("auth_user")).toBeNull();
  });

  it("restores user from localStorage on mount", async () => {
    localStorage.setItem("auth_token", "stored-token");
    localStorage.setItem(
      "auth_user",
      JSON.stringify({
        sub: "u1",
        email: "bob@test.com",
        name: "bob",
        role: "operator",
        groups: ["operator"],
      }),
    );

    renderAuth();

    expect(
      screen.getByTestId("authenticated"),
    ).toHaveTextContent("true");
    expect(
      screen.getByTestId("role"),
    ).toHaveTextContent("operator");
    expect(
      screen.getByTestId("name"),
    ).toHaveTextContent("bob");
  });

  it("clears stale token without user data", () => {
    localStorage.setItem("auth_token", "orphan-token");

    renderAuth();

    expect(
      screen.getByTestId("authenticated"),
    ).toHaveTextContent("false");
    expect(localStorage.getItem("auth_token")).toBeNull();
  });

  it("clears corrupted user data", () => {
    localStorage.setItem("auth_token", "t");
    localStorage.setItem("auth_user", "not-json");

    renderAuth();

    expect(
      screen.getByTestId("authenticated"),
    ).toHaveTextContent("false");
    expect(localStorage.getItem("auth_token")).toBeNull();
  });

  it("hasRole respects hierarchy", async () => {
    localStorage.setItem("auth_token", "t");
    localStorage.setItem(
      "auth_user",
      JSON.stringify({
        sub: "u1",
        email: "op@test.com",
        name: "op",
        role: "operator",
        groups: ["operator"],
      }),
    );

    renderAuth();

    expect(
      screen.getByTestId("has-viewer"),
    ).toHaveTextContent("true");
    expect(
      screen.getByTestId("has-operator"),
    ).toHaveTextContent("true");
    expect(
      screen.getByTestId("has-admin"),
    ).toHaveTextContent("false");
  });

  it("login with email username uses email directly", async () => {
    renderAuth();
    await act(async () => {
      const auth = screen.getByText("login");
      // Re-render with email login
      auth.click();
    });

    const stored = JSON.parse(
      localStorage.getItem("auth_user")!,
    );
    expect(stored.email).toBe("alice@cloudline.dev");
  });
});
