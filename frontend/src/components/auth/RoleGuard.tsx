import type { ReactNode } from "react";
import type { UserRole } from "@/types";
import { useAuth } from "@/hooks/useAuth";

interface Props {
  required: UserRole;
  children: ReactNode;
  fallback?: ReactNode;
}

export default function RoleGuard({
  required,
  children,
  fallback,
}: Props) {
  const { hasRole } = useAuth();

  if (!hasRole(required)) {
    return fallback ? (
      <>{fallback}</>
    ) : (
      <div className="p-4 text-center text-sm text-gray-400 dark:text-gray-500">
        Insufficient permissions. Requires{" "}
        <span className="font-medium capitalize">
          {required}
        </span>{" "}
        role or above.
      </div>
    );
  }

  return <>{children}</>;
}
