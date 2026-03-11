import { useMemo, useState } from "react";
import {
  useRemediations,
  useRemediationDetail,
} from "@/hooks";
import { useViolations } from "@/hooks";
import {
  RemediationList,
  RemediationDetail,
  ExecutePanel,
  RollbackPanel,
  AuditTrail,
  AutoConfigPanel,
} from "@/components/remediation";

type Tab = "suggestions" | "audit" | "config";

const TABS: { key: Tab; label: string }[] = [
  { key: "suggestions", label: "Suggestions" },
  { key: "audit", label: "Audit Trail" },
  { key: "config", label: "Auto-Remediation" },
];

export default function RemediationPage() {
  const [tab, setTab] = useState<Tab>("suggestions");
  const [selectedId, setSelectedId] = useState<
    string | null
  >(null);

  const remediations = useRemediations();
  const violations = useViolations({ status: "alarm" });
  const detail = useRemediationDetail(selectedId);

  // Only show remediations for currently violated checks
  const affectedItems = useMemo(() => {
    if (!remediations.data || !violations.data) return [];
    const violatedChecks = new Set(
      violations.data.map((v) => v.check_id),
    );
    return remediations.data.remediations.filter(
      (r) => violatedChecks.has(r.check_id),
    );
  }, [remediations.data, violations.data]);

  return (
    <div>
      <h2 className="text-xl font-semibold text-gray-900 dark:text-white mb-6">
        Remediation
      </h2>

      {/* Tab bar */}
      <div className="border-b border-gray-200 dark:border-gray-700 mb-6">
        <div className="flex gap-0">
          {TABS.map((t) => (
            <button
              key={t.key}
              onClick={() => setTab(t.key)}
              className={`px-4 py-2.5 text-sm font-medium border-b-2 transition-colors ${
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

      {/* Suggestions tab */}
      {tab === "suggestions" && (
        <div>
          {remediations.isLoading && (
            <div className="animate-pulse space-y-2">
              {Array.from({ length: 5 }).map((_, i) => (
                <div
                  key={i}
                  className="h-20 bg-gray-100 dark:bg-gray-700 rounded-lg"
                />
              ))}
            </div>
          )}

          {remediations.error && (
            <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-4">
              <p className="text-sm text-red-700 dark:text-red-400">
                Failed to load remediations.
              </p>
            </div>
          )}

          {remediations.data && (
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Left: List */}
              <div className="lg:col-span-1 max-h-[calc(100vh-220px)] overflow-y-auto pr-1">
                <RemediationList
                  items={affectedItems}
                  selectedId={selectedId}
                  onSelect={setSelectedId}
                />
              </div>

              {/* Right: Detail */}
              <div className="lg:col-span-2">
                {selectedId && detail.data ? (
                  <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6 space-y-6">
                    <RemediationDetail
                      item={detail.data}
                    />
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <ExecutePanel
                        remediationId={selectedId}
                      />
                      <RollbackPanel
                        remediationId={selectedId}
                      />
                    </div>
                  </div>
                ) : selectedId && detail.isLoading ? (
                  <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
                    <div className="animate-pulse space-y-3">
                      <div className="h-6 w-48 bg-gray-200 dark:bg-gray-700 rounded" />
                      <div className="h-4 w-32 bg-gray-100 dark:bg-gray-700 rounded" />
                      <div className="h-32 bg-gray-100 dark:bg-gray-700 rounded mt-4" />
                    </div>
                  </div>
                ) : (
                  <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-8 text-center">
                    <p className="text-sm text-gray-500 dark:text-gray-400">
                      Select a remediation to view
                      details.
                    </p>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Audit Trail tab */}
      {tab === "audit" && (
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
          <h3 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-4">
            Remediation Audit Trail
          </h3>
          <AuditTrail />
        </div>
      )}

      {/* Auto-Remediation Config tab */}
      {tab === "config" && (
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
          <h3 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-4">
            Auto-Remediation Configuration
          </h3>
          <AutoConfigPanel />
        </div>
      )}
    </div>
  );
}
