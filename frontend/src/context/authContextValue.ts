import { createContext } from "react";
import type {
  AuthUser,
  LoginCredentials,
  UserRole,
} from "@/types";

export interface AuthContextValue {
  user: AuthUser | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  role: UserRole | null;
  login: (creds: LoginCredentials) => Promise<void>;
  logout: () => void;
  hasRole: (required: UserRole) => boolean;
}

export const AuthContext =
  createContext<AuthContextValue>(
    null as unknown as AuthContextValue,
  );
