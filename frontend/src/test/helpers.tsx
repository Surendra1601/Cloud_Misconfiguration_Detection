import type { ReactNode } from "react";
import { render } from "@testing-library/react";
import type { RenderOptions } from "@testing-library/react";
import {
  QueryClient,
  QueryClientProvider,
} from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { AuthProvider } from "@/context/AuthContext";
import { AlertProvider } from "@/context/AlertContext";

function createTestQueryClient() {
  return new QueryClient({
    defaultOptions: {
      queries: { retry: false, gcTime: 0 },
      mutations: { retry: false },
    },
  });
}

interface WrapperOptions {
  route?: string;
  authenticated?: boolean;
}

function createWrapper(opts: WrapperOptions = {}) {
  const { route = "/", authenticated = false } = opts;

  if (authenticated) {
    localStorage.setItem("auth_token", "test-token");
    localStorage.setItem(
      "auth_user",
      JSON.stringify({
        sub: "test-user",
        email: "test@cloudline.dev",
        name: "test",
        role: "admin",
        groups: ["admin"],
      }),
    );
  }

  const qc = createTestQueryClient();

  return function Wrapper({
    children,
  }: {
    children: ReactNode;
  }) {
    return (
      <QueryClientProvider client={qc}>
        <AuthProvider>
          <AlertProvider>
            <MemoryRouter initialEntries={[route]}>
              {children}
            </MemoryRouter>
          </AlertProvider>
        </AuthProvider>
      </QueryClientProvider>
    );
  };
}

export function renderWithProviders(
  ui: React.ReactElement,
  opts: WrapperOptions & RenderOptions = {},
) {
  const { route, authenticated, ...renderOpts } =
    opts;
  const Wrapper = createWrapper({
    route,
    authenticated,
  });
  return render(ui, { wrapper: Wrapper, ...renderOpts });
}

export { createTestQueryClient };
