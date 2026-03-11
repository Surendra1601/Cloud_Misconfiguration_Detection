import { render, screen } from "@testing-library/react";
import {
  MemoryRouter,
  Route,
  Routes,
} from "react-router-dom";
import { AuthProvider } from "@/context/AuthContext";
import ProtectedRoute from "../ProtectedRoute";

function renderWithAuth(authenticated: boolean) {
  if (authenticated) {
    localStorage.setItem("auth_token", "t");
    localStorage.setItem(
      "auth_user",
      JSON.stringify({
        sub: "u1",
        email: "a@b.com",
        name: "a",
        role: "admin",
        groups: ["admin"],
      }),
    );
  }

  return render(
    <AuthProvider>
      <MemoryRouter initialEntries={["/protected"]}>
        <Routes>
          <Route
            path="/protected"
            element={
              <ProtectedRoute>
                <div>Secret Content</div>
              </ProtectedRoute>
            }
          />
          <Route
            path="/login"
            element={<div>Login Page</div>}
          />
        </Routes>
      </MemoryRouter>
    </AuthProvider>,
  );
}

describe("ProtectedRoute", () => {
  it("renders children when authenticated", () => {
    renderWithAuth(true);
    expect(
      screen.getByText("Secret Content"),
    ).toBeInTheDocument();
  });

  it("redirects to login when not authenticated", () => {
    renderWithAuth(false);
    expect(
      screen.getByText("Login Page"),
    ).toBeInTheDocument();
    expect(
      screen.queryByText("Secret Content"),
    ).not.toBeInTheDocument();
  });
});
