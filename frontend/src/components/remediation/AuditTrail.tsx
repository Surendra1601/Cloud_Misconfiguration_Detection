import { useAuditTrail } from "@/hooks";
import { StatusBadge } from "@/components/shared";
import { getCheckName } from "@/constants/checkNames";

const TIER_LABELS: Record<string, string> = {
  tier_1_suggestion: "Suggestion",
  tier_2_oneclick: "One-Click",
  tier_3_auto: "Auto",
};

export default function AuditTrail() {
  const { data, isLoading, error } = useAuditTrail();

  if (isLoading) {
    return (
      <div className="animate-pulse space-y-2">
        {Array.from({ length: 5 }).map((_, i) => (
          <div
            key={i}
            className="h-12 bg-gray-100 dark:bg-gray-700 rounded"
          />
        ))}
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded p-3">
        <p className="text-sm text-red-700 dark:text-red-400">
          Failed to load audit trail.
        </p>
      </div>
    );
  }

  if (!data || data.entries.length === 0) {
    return (
      <div className="text-center py-8">
        <p className="text-sm font-medium text-gray-500 dark:text-gray-400">
          No audit entries yet
        </p>
        <p className="text-xs text-gray-400 dark:text-gray-500 mt-1">
          Execute a remediation fix to see
          audit entries here.
        </p>
      </div>
    );
  }

  return (
    <div className="overflow-x-auto rounded-lg border border-gray-200 dark:border-gray-700">
      <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
        <thead className="bg-gray-50 dark:bg-gray-800">
          <tr>
            <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">
              Action ID
            </th>
            <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">
              Check
            </th>
            <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">
              Tier
            </th>
            <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">
              Status
            </th>
            <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">
              By
            </th>
            <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">
              Date
            </th>
          </tr>
        </thead>
        <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
          {data.entries.map((entry) => (
            <tr key={entry.action_id}>
              <td className="px-3 py-2.5 text-xs font-mono text-gray-900 dark:text-gray-100 max-w-[120px] truncate">
                {entry.action_id}
              </td>
              <td className="px-3 py-2.5">
                <span className="text-xs text-gray-900 dark:text-gray-100 block">
                  {getCheckName(entry.check_id)}
                </span>
                <span className="text-[10px] font-mono text-gray-400 dark:text-gray-500">
                  {entry.check_id}
                </span>
              </td>
              <td className="px-3 py-2.5 text-xs text-gray-700 dark:text-gray-300">
                {TIER_LABELS[entry.tier] ?? entry.tier}
              </td>
              <td className="px-3 py-2.5">
                <StatusBadge status={entry.status} />
              </td>
              <td className="px-3 py-2.5 text-xs text-gray-700 dark:text-gray-300">
                {entry.initiated_by || "—"}
              </td>
              <td className="px-3 py-2.5 text-xs text-gray-500 dark:text-gray-400">
                {new Date(
                  entry.created_at,
                ).toLocaleString()}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
