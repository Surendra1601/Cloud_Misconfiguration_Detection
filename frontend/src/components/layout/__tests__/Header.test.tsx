import {
  render,
  screen,
  act,
} from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AlertProvider } from "@/context/AlertContext";
import { AuthProvider } from "@/context/AuthContext";
import Header from "../Header";

function renderHeader() {
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

  return render(
    <AuthProvider>
      <AlertProvider>
        <Header />
      </AlertProvider>
    </AuthProvider>,
  );
}

describe("Header", () => {
  it("renders dark mode toggle", () => {
    renderHeader();
    expect(
      screen.getByLabelText("Toggle dark mode"),
    ).toBeInTheDocument();
  });

  it("renders notification bell", () => {
    renderHeader();
    expect(
      screen.getByLabelText("Notifications"),
    ).toBeInTheDocument();
  });

  it("shows ws status", () => {
    renderHeader();
    expect(
      screen.getByText("Offline"),
    ).toBeInTheDocument();
  });

  it("toggles dark mode", async () => {
    const user = userEvent.setup();
    renderHeader();

    await user.click(
      screen.getByLabelText("Toggle dark mode"),
    );
    expect(
      document.documentElement.classList.contains(
        "dark",
      ),
    ).toBe(true);

    await user.click(
      screen.getByLabelText("Toggle dark mode"),
    );
    expect(
      document.documentElement.classList.contains(
        "dark",
      ),
    ).toBe(false);
  });

  it("toggles notification feed", async () => {
    const user = userEvent.setup();
    renderHeader();

    await user.click(
      screen.getByLabelText("Notifications"),
    );
    expect(
      screen.getByText("Live Alerts"),
    ).toBeInTheDocument();
  });
});
