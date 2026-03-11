import {
  createBrowserRouter,
  Navigate,
  RouterProvider,
} from "react-router-dom";
import {
  QueryClient,
  QueryClientProvider,
} from "@tanstack/react-query";
import { AuthProvider } from "@/context/AuthContext";
import { AlertProvider } from "@/context/AlertContext";
import { ProtectedRoute } from "@/components/auth";
import { Layout } from "@/components/layout";
import {
  DashboardPage,
  ViolationsPage,
  TrendsPage,
  ExecutiveSummaryPage,
  RemediationPage,
  PoliciesPage,
  LoginPage,
} from "@/pages";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      staleTime: 10_000,
    },
  },
});

const router = createBrowserRouter([
  {
    path: "/login",
    element: <LoginPage />,
  },
  {
    path: "/",
    element: (
      <ProtectedRoute>
        <Layout />
      </ProtectedRoute>
    ),
    children: [
      {
        index: true,
        element: <Navigate to="/dashboard" replace />,
      },
      {
        path: "dashboard",
        element: <DashboardPage />,
      },
      {
        path: "violations",
        element: <ViolationsPage />,
      },
      {
        path: "trends",
        element: <TrendsPage />,
      },
      {
        path: "remediation",
        element: <RemediationPage />,
      },
      {
        path: "executive",
        element: <ExecutiveSummaryPage />,
      },
      {
        path: "policies",
        element: <PoliciesPage />,
      },
    ],
  },
]);

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <AlertProvider>
          <RouterProvider router={router} />
        </AlertProvider>
      </AuthProvider>
    </QueryClientProvider>
  );
}

export default App;
