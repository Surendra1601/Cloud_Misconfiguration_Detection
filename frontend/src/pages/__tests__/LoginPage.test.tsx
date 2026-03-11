import {
  render,
  screen,
  act,
} from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import {
  MemoryRouter,
  Route,
  Routes,
} from "react-router-dom";
import { AuthProvider } from "@/context/AuthContext";
import LoginPage from "../LoginPage";

function renderLogin(route = "/login") {
  return render(
    <AuthProvider>
      <MemoryRouter initialEntries={[route]}>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route
            path="/dashboard"
            element={<div>Dashboard</div>}
          />
        </Routes>
      </MemoryRouter>
    </AuthProvider>,
  );
}

describe("LoginPage", () => {
  it("renders login form", () => {
    renderLogin();
    expect(
      screen.getByLabelText("Username"),
    ).toBeInTheDocument();
    expect(
      screen.getByLabelText("Password"),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Sign in" }),
    ).toBeInTheDocument();
  });

  it("shows CloudLine branding", () => {
    renderLogin();
    expect(
      screen.getByText("CloudLine"),
    ).toBeInTheDocument();
    expect(
      screen.getByText("Compliance Dashboard"),
    ).toBeInTheDocument();
  });

  it("shows local mode hint", () => {
    renderLogin();
    expect(
      screen.getByText(/local mode/i),
    ).toBeInTheDocument();
  });

  it("shows error for empty fields", async () => {
    const user = userEvent.setup();
    renderLogin();

    await user.click(
      screen.getByRole("button", { name: "Sign in" }),
    );

    expect(
      screen.getByText(
        "Please enter username and password",
      ),
    ).toBeInTheDocument();
  });

  it("successful login redirects to dashboard", async () => {
    const user = userEvent.setup();
    renderLogin();

    await user.type(
      screen.getByLabelText("Username"),
      "alice",
    );
    await user.type(
      screen.getByLabelText("Password"),
      "pass123",
    );
    await user.click(
      screen.getByRole("button", { name: "Sign in" }),
    );

    expect(
      screen.getByText("Dashboard"),
    ).toBeInTheDocument();
  });

  it("redirects already authenticated user", () => {
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

    renderLogin();

    expect(
      screen.getByText("Dashboard"),
    ).toBeInTheDocument();
  });
});
