import { useState } from "react";
import {
  useQuery,
  useMutation,
  useQueryClient,
} from "@tanstack/react-query";
import {
  getPolicies,
  createPolicy,
  deletePolicy,
  type CreatePolicyRequest,
} from "@/api/policies";
import { getCheckName } from "@/constants/checkNames";
import SeverityBadge from "@/components/shared/SeverityBadge";

const DOMAINS = [
  "identity",
  "data_protection",
  "network",
  "logging",
  "detection",
] as const;

const SEVERITIES = [
  "critical",
  "high",
  "medium",
  "low",
] as const;

const EMPTY_FORM: CreatePolicyRequest = {
  check_id: "",
  name: "",
  domain: "",
  severity: "",
  description: "",
  input_field: "",
  resource_path: "",
  condition_field: "",
  condition_value: "",
  compliance_cis: "",
  compliance_nist: "",
  compliance_pci: "",
  remediation_id: "",
};

export default function PoliciesPage() {
  const queryClient = useQueryClient();
  const [form, setForm] =
    useState<CreatePolicyRequest>(EMPTY_FORM);
  const [feedback, setFeedback] = useState<{
    type: "success" | "error";
    message: string;
  } | null>(null);

  const {
    data: policies,
    isLoading,
    error,
  } = useQuery({
    queryKey: ["policies"],
    queryFn: getPolicies,
  });

  const createMutation = useMutation({
    mutationFn: createPolicy,
    onSuccess: (res) => {
      queryClient.invalidateQueries({
        queryKey: ["policies"],
      });
      setForm(EMPTY_FORM);
      setFeedback({
        type: "success",
        message: `Policy ${res.check_id} created.`,
      });
    },
    onError: (err: { message?: string }) => {
      setFeedback({
        type: "error",
        message:
          err.message ?? "Failed to create policy.",
      });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: deletePolicy,
    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: ["policies"],
      });
      setFeedback({
        type: "success",
        message: "Policy deleted.",
      });
    },
    onError: (err: { message?: string }) => {
      setFeedback({
        type: "error",
        message:
          err.message ?? "Failed to delete policy.",
      });
    },
  });

  function handleChange(
    e: React.ChangeEvent<
      | HTMLInputElement
      | HTMLSelectElement
      | HTMLTextAreaElement
    >,
  ) {
    setForm((prev) => ({
      ...prev,
      [e.target.name]: e.target.value,
    }));
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setFeedback(null);
    createMutation.mutate(form);
  }

  function handleDelete(checkId: string) {
    setFeedback(null);
    deleteMutation.mutate(checkId);
  }

  const inputCls =
    "w-full rounded-lg border border-gray-200" +
    " dark:border-white/10 bg-white dark:bg-white/5" +
    " px-3 py-2 text-sm text-gray-900" +
    " dark:text-gray-100 placeholder-gray-400" +
    " dark:placeholder-gray-600" +
    " focus:outline-none focus:ring-2" +
    " focus:ring-blue-500/40 transition-colors";

  const labelCls =
    "block text-xs font-medium text-gray-600" +
    " dark:text-gray-400 mb-1";

  return (
    <div className="space-y-4">
      <h2
        className={
          "text-xl font-bold text-gray-900" +
          " dark:text-white tracking-tight"
        }
      >
        Rego Policies
      </h2>

      {/* Feedback banner */}
      {feedback && (
        <div
          className={`rounded-xl border p-4 text-sm ${
            feedback.type === "success"
              ? "bg-green-50 dark:bg-green-500/5" +
                " border-green-200" +
                " dark:border-green-500/20" +
                " text-green-700 dark:text-green-400"
              : "bg-red-50 dark:bg-red-500/5" +
                " border-red-200" +
                " dark:border-red-500/20" +
                " text-red-700 dark:text-red-400"
          }`}
        >
          {feedback.message}
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Left: Policy list */}
        <div
          className={
            "bg-white dark:bg-[#111] border" +
            " border-gray-100 dark:border-white/5" +
            " rounded-2xl p-5 shadow-sm"
          }
        >
          <h3
            className={
              "text-sm font-semibold text-gray-800" +
              " dark:text-gray-200 mb-4"
            }
          >
            Existing Policies
          </h3>

          {isLoading && (
            <div className="animate-pulse space-y-2">
              {Array.from({ length: 6 }).map((_, i) => (
                <div
                  key={i}
                  className={
                    "h-16 bg-gray-100" +
                    " dark:bg-white/5 rounded-xl"
                  }
                />
              ))}
            </div>
          )}

          {error && (
            <p className="text-sm text-red-600 dark:text-red-400">
              Failed to load policies:{" "}
              {(error as { message?: string }).message ??
                "Unknown error"}
            </p>
          )}

          {policies && policies.length === 0 && (
            <p className="text-sm text-gray-500 dark:text-gray-500">
              No policies found.
            </p>
          )}

          {policies && policies.length > 0 && (
            <div className="space-y-2 max-h-[70vh] overflow-y-auto pr-1">
              {policies.map((p) => (
                <div
                  key={p.check_id}
                  className={
                    "flex items-center justify-between" +
                    " rounded-xl border border-gray-100" +
                    " dark:border-white/5 bg-gray-50" +
                    " dark:bg-white/[0.02] px-4 py-3"
                  }
                >
                  <div className="min-w-0 flex-1">
                    <p
                      className={
                        "text-sm font-medium" +
                        " text-gray-900 dark:text-white" +
                        " truncate"
                      }
                    >
                      {p.check_id}
                      <span className="ml-2 text-gray-500 dark:text-gray-400 font-normal">
                        {getCheckName(p.check_id)}
                      </span>
                    </p>
                    <div className="flex items-center gap-2 mt-1">
                      <span
                        className={
                          "text-xs text-gray-500" +
                          " dark:text-gray-500 capitalize"
                        }
                      >
                        {p.domain.replace("_", " ")}
                      </span>
                      <SeverityBadge
                        severity={p.severity}
                      />
                    </div>
                  </div>
                  <button
                    onClick={() =>
                      handleDelete(p.check_id)
                    }
                    disabled={deleteMutation.isPending}
                    className={
                      "ml-3 shrink-0 p-1.5 rounded-lg" +
                      " text-gray-400" +
                      " hover:text-red-600" +
                      " dark:hover:text-red-400" +
                      " hover:bg-red-50" +
                      " dark:hover:bg-red-500/10" +
                      " transition-colors" +
                      " disabled:opacity-50"
                    }
                    title={`Delete ${p.check_id}`}
                  >
                    <svg
                      className="w-4 h-4"
                      fill="none"
                      stroke="currentColor"
                      viewBox="0 0 24 24"
                    >
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth="1.8"
                        d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"
                      />
                    </svg>
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Right: Create form */}
        <div
          className={
            "bg-white dark:bg-[#111] border" +
            " border-gray-100 dark:border-white/5" +
            " rounded-2xl p-5 shadow-sm"
          }
        >
          <h3
            className={
              "text-sm font-semibold text-gray-800" +
              " dark:text-gray-200 mb-4"
            }
          >
            Add New Policy
          </h3>

          <form
            onSubmit={handleSubmit}
            className="space-y-3"
          >
            {/* Check ID */}
            <div>
              <label className={labelCls}>Check ID</label>
              <input
                name="check_id"
                value={form.check_id}
                onChange={handleChange}
                placeholder="CHECK_21"
                required
                className={inputCls}
              />
            </div>

            {/* Name */}
            <div>
              <label className={labelCls}>Name</label>
              <input
                name="name"
                value={form.name}
                onChange={handleChange}
                placeholder="S3 Versioning Disabled"
                required
                className={inputCls}
              />
            </div>

            {/* Domain + Severity row */}
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className={labelCls}>Domain</label>
                <select
                  name="domain"
                  value={form.domain}
                  onChange={handleChange}
                  required
                  className={inputCls}
                >
                  <option value="">Select...</option>
                  {DOMAINS.map((d) => (
                    <option key={d} value={d}>
                      {d.replace("_", " ")}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className={labelCls}>
                  Severity
                </label>
                <select
                  name="severity"
                  value={form.severity}
                  onChange={handleChange}
                  required
                  className={inputCls}
                >
                  <option value="">Select...</option>
                  {SEVERITIES.map((s) => (
                    <option key={s} value={s}>
                      {s}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            {/* Description */}
            <div>
              <label className={labelCls}>
                Description
              </label>
              <textarea
                name="description"
                value={form.description}
                onChange={handleChange}
                placeholder="Detects S3 buckets without..."
                required
                rows={2}
                className={inputCls}
              />
            </div>

            {/* Input Field + Resource Path */}
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className={labelCls}>
                  Input Field
                </label>
                <input
                  name="input_field"
                  value={form.input_field}
                  onChange={handleChange}
                  placeholder="s3"
                  required
                  className={inputCls}
                />
              </div>
              <div>
                <label className={labelCls}>
                  Resource Path
                </label>
                <input
                  name="resource_path"
                  value={form.resource_path}
                  onChange={handleChange}
                  placeholder="input.s3.buckets[_]"
                  required
                  className={inputCls}
                />
              </div>
            </div>

            {/* Condition Field + Value */}
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className={labelCls}>
                  Condition Field
                </label>
                <input
                  name="condition_field"
                  value={form.condition_field}
                  onChange={handleChange}
                  placeholder="versioning_enabled"
                  required
                  className={inputCls}
                />
              </div>
              <div>
                <label className={labelCls}>
                  Condition Value
                </label>
                <input
                  name="condition_value"
                  value={form.condition_value}
                  onChange={handleChange}
                  placeholder="false"
                  required
                  className={inputCls}
                />
              </div>
            </div>

            {/* Compliance row */}
            <div className="grid grid-cols-3 gap-3">
              <div>
                <label className={labelCls}>
                  Compliance CIS
                </label>
                <input
                  name="compliance_cis"
                  value={form.compliance_cis}
                  onChange={handleChange}
                  placeholder="2.1.3"
                  className={inputCls}
                />
              </div>
              <div>
                <label className={labelCls}>
                  Compliance NIST
                </label>
                <input
                  name="compliance_nist"
                  value={form.compliance_nist}
                  onChange={handleChange}
                  placeholder="SC-28"
                  className={inputCls}
                />
              </div>
              <div>
                <label className={labelCls}>
                  Compliance PCI
                </label>
                <input
                  name="compliance_pci"
                  value={form.compliance_pci}
                  onChange={handleChange}
                  placeholder="3.4"
                  className={inputCls}
                />
              </div>
            </div>

            {/* Remediation ID */}
            <div>
              <label className={labelCls}>
                Remediation ID
              </label>
              <input
                name="remediation_id"
                value={form.remediation_id}
                onChange={handleChange}
                placeholder="REM_21"
                className={inputCls}
              />
            </div>

            {/* Submit */}
            <button
              type="submit"
              disabled={createMutation.isPending}
              className={
                "w-full mt-2 px-4 py-2.5 rounded-xl" +
                " text-sm font-medium text-white" +
                " bg-blue-600 hover:bg-blue-700" +
                " dark:bg-blue-500" +
                " dark:hover:bg-blue-600" +
                " disabled:opacity-50" +
                " transition-colors"
              }
            >
              {createMutation.isPending
                ? "Creating..."
                : "Create Policy"}
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}
