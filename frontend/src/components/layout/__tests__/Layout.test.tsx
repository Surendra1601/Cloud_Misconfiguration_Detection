import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { AuthProvider } from "@/context/AuthContext";
import { AlertProvider } from "@/context/AlertContext";
import type { ReactNode } from "react";
import {
  QueryClient,
  QueryClientProvider,
} from "@tanstack/react-query";

// Mock useWebSocket to avoid real WS connections
vi.mock("@/hooks/useWebSocket", () => ({
  useWebSocket: () => {},
}));

import Layout from "../Layout";

function Wrapper({ children }: { children: ReactNode }) {
  const qc = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
    },
  });

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

  return (
    <QueryClientProvider client={qc}>
      <AuthProvider>
        <AlertProvider>
          <MemoryRouter>{children}</MemoryRouter>
        </AlertProvider>
      </AuthProvider>
    </QueryClientProvider>
  );
}

describe("Layout", () => {
  it("renders sidebar and header", () => {
    render(
      <Wrapper>
        <Layout />
      </Wrapper>,
    );
    expect(
      screen.getByText("CloudLine"),
    ).toBeInTheDocument();
    expect(
      screen.getByLabelText("Toggle dark mode"),
    ).toBeInTheDocument();
  });

  it("renders nav links", () => {
    render(
      <Wrapper>
        <Layout />
      </Wrapper>,
    );
    expect(
      screen.getByText("Dashboard"),
    ).toBeInTheDocument();
    expect(
      screen.getByText("Violations"),
    ).toBeInTheDocument();
  });
});
