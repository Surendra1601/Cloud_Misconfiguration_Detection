import { renderHook } from "@testing-library/react";
import type { ReactNode } from "react";
import { AuthProvider } from "@/context/AuthContext";
import { useAuth } from "../useAuth";

function wrapper({ children }: { children: ReactNode }) {
  return <AuthProvider>{children}</AuthProvider>;
}

describe("useAuth", () => {
  it("throws outside AuthProvider", () => {
    expect(() =>
      renderHook(() => useAuth()),
    ).toThrow("useAuth must be used within AuthProvider");
  });

  it("returns auth context inside provider", () => {
    const { result } = renderHook(() => useAuth(), {
      wrapper,
    });

    expect(result.current.isAuthenticated).toBe(false);
    expect(result.current.user).toBeNull();
    expect(result.current.role).toBeNull();
    expect(result.current.isLoading).toBe(false);
    expect(typeof result.current.login).toBe("function");
    expect(typeof result.current.logout).toBe("function");
    expect(typeof result.current.hasRole).toBe(
      "function",
    );
  });
});
