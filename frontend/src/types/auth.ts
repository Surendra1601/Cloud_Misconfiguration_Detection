export type UserRole = "viewer" | "operator" | "admin";

export interface AuthUser {
  sub: string;
  email: string;
  name?: string;
  role: UserRole;
  groups: string[];
}

export interface LoginCredentials {
  username: string;
  password: string;
}
