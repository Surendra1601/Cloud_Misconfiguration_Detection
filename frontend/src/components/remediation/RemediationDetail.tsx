import { useState } from "react";
import type { RemediationTemplate } from "@/types";
import { SeverityBadge } from "@/components/shared";

interface Props {
  item: RemediationTemplate;
}

type Tab = "console" | "cli" | "terraform";

const TABS: { key: Tab; label: string }[] = [
  { key: "console", label: "Console" },
  { key: "cli", label: "CLI" },
  { key: "terraform", label: "Terraform" },
];

export default function RemediationDetail({
  item,
}: Props) {
  const [tab, setTab] = useState<Tab>("console");

  return (
    <div className="space-y-5">
      {/* Header */}
      <div>
        <div className="flex items-center gap-2 mb-1">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
            {item.title}
          </h3>
          <SeverityBadge severity={item.severity} />
        </div>
        <p className="text-xs font-mono text-gray-500 dark:text-gray-400">
          {item.remediation_id} / {item.check_id}
        </p>
      </div>

      {/* Meta */}
      <div className="flex flex-wrap gap-4 text-sm text-gray-600 dark:text-gray-300">
        <span>
          Fix time: ~{item.estimated_fix_time_minutes}m
        </span>
        {item.risk_reduction && (
          <span>Risk reduction: {item.risk_reduction}</span>
        )}
        {item.rollback_difficulty && (
          <span>
            Rollback: {item.rollback_difficulty}
          </span>
        )}
      </div>

      {/* Tabs */}
      <div className="border-b border-gray-200 dark:border-gray-700">
        <div className="flex gap-0">
          {TABS.map((t) => (
            <button
              key={t.key}
              onClick={() => setTab(t.key)}
              className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
                tab === t.key
                  ? "border-primary-500 text-primary-600 dark:text-primary-400"
                  : "border-transparent text-gray-500 hover:text-gray-700 dark:text-gray-400"
              }`}
            >
              {t.label}
            </button>
          ))}
        </div>
      </div>

      {/* Tab Content */}
      <div className="min-h-[120px]">
        {tab === "console" && (
          <div className="space-y-2">
            {item.console_steps.length === 0 ? (
              <p className="text-sm text-gray-400">
                No console steps available.
              </p>
            ) : (
              <ol className="list-decimal list-inside space-y-1.5">
                {item.console_steps.map((step, i) => (
                  <li
                    key={i}
                    className="text-sm text-gray-700 dark:text-gray-300"
                  >
                    {step}
                  </li>
                ))}
              </ol>
            )}
          </div>
        )}

        {tab === "cli" && (
          <div className="space-y-3">
            {item.cli_command ? (
              <>
                <div>
                  <p className="text-xs font-medium text-gray-500 dark:text-gray-400 mb-1">
                    Command
                  </p>
                  <pre className="bg-gray-900 text-green-400 text-sm p-3 rounded-lg overflow-x-auto">
                    {item.cli_command}
                  </pre>
                </div>
                {item.cli_example && (
                  <div>
                    <p className="text-xs font-medium text-gray-500 dark:text-gray-400 mb-1">
                      Example
                    </p>
                    <pre className="bg-gray-900 text-green-400 text-sm p-3 rounded-lg overflow-x-auto">
                      {item.cli_example}
                    </pre>
                  </div>
                )}
              </>
            ) : (
              <p className="text-sm text-gray-400">
                No CLI command available.
              </p>
            )}
          </div>
        )}

        {tab === "terraform" && (
          <div>
            {item.terraform_snippet ? (
              <pre className="bg-gray-900 text-green-400 text-sm p-3 rounded-lg overflow-x-auto">
                {item.terraform_snippet}
              </pre>
            ) : (
              <p className="text-sm text-gray-400">
                No Terraform snippet available.
              </p>
            )}
          </div>
        )}
      </div>

      {/* Compliance References */}
      {item.references.length > 0 && (
        <div>
          <h4 className="text-xs font-semibold text-gray-900 dark:text-white mb-2 uppercase tracking-wider">
            Compliance References
          </h4>
          <div className="space-y-1">
            {item.references.map((ref, i) => (
              <p
                key={i}
                className="text-xs text-gray-600 dark:text-gray-400"
              >
                <span className="font-medium">
                  {ref.framework}
                </span>{" "}
                {ref.control_id}
                {ref.title && ` — ${ref.title}`}
              </p>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
