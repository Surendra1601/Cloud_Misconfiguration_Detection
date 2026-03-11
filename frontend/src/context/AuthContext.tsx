import { useCallback, useMemo, useState } from "react";
import type { ReactNode } from "react";
import type {
  AuthUser,
  LoginCredentials,
  UserRole,
} from "@/types";
import { AuthContext } from "./authContextValue";
import axios from "axios";

const TOKEN_KEY = "auth_token";
const USER_KEY = "auth_user";

const ROLE_LEVELS: Record<UserRole, number> = {
  viewer: 1,
  operator: 2,
  admin: 3,
};

function loadInitialUser(): AuthUser | null {
  try {
    const raw = localStorage.getItem(USER_KEY);
    const token = localStorage.getItem(TOKEN_KEY);
    if (!raw || !token) {
      localStorage.removeItem(TOKEN_KEY);
      localStorage.removeItem(USER_KEY);
      return null;
    }
    return JSON.parse(raw) as AuthUser;
  } catch {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
    return null;
  }
}

export function AuthProvider({
  children,
}: {
  children: ReactNode;
}) {
  const [user, setUser] = useState<AuthUser | null>(
    loadInitialUser,
  );

  const login = useCallback(
    async (creds: LoginCredentials) => {
      const baseUrl =
        import.meta.env.VITE_API_BASE_URL || "/api";
      const { data } = await axios.post(
        `${baseUrl}/v1/auth/login`,
        {
          username: creds.username,
          password: creds.password,
        },
      );

      const authUser: AuthUser = {
        sub: data.user.sub,
        email: data.user.email,
        name: data.user.name,
        role: data.user.role,
        groups: [data.user.role],
      };

      localStorage.setItem(TOKEN_KEY, data.token);
      localStorage.setItem(
        USER_KEY,
        JSON.stringify(authUser),
      );
      setUser(authUser);
    },
    [],
  );

  const logout = useCallback(() => {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
    setUser(null);
  }, []);

  const hasRole = useCallback(
    (required: UserRole): boolean => {
      if (!user) return false;
      return (
        ROLE_LEVELS[user.role] >=
        ROLE_LEVELS[required]
      );
    },
    [user],
  );

  const value = useMemo(
    () => ({
      user,
      isAuthenticated: !!user,
      isLoading: false,
      role: user?.role ?? null,
      login,
      logout,
      hasRole,
    }),
    [user, login, logout, hasRole],
  );

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
}
