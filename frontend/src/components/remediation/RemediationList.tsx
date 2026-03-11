import type { RemediationTemplate } from "@/types";
import { SeverityBadge } from "@/components/shared";
import { getCheckName } from "@/constants/checkNames";

interface Props {
  items: RemediationTemplate[];
  selectedId: string | null;
  onSelect: (id: string) => void;
}

export default function RemediationList({
  items,
  selectedId,
  onSelect,
}: Props) {
  if (items.length === 0) {
    return (
      <p className="text-sm text-gray-500 dark:text-gray-400 p-4">
        No remediation suggestions available.
      </p>
    );
  }

  return (
    <div className="space-y-2">
      {items.map((item) => (
        <button
          key={item.remediation_id}
          onClick={() => onSelect(item.remediation_id)}
          className={`w-full text-left rounded-lg border p-4 transition-colors ${
            selectedId === item.remediation_id
              ? "border-primary-500 bg-primary-50 dark:bg-primary-900/20"
              : "border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700/50"
          }`}
        >
          <div className="flex items-start justify-between gap-2">
            <div className="min-w-0">
              <p className="text-sm font-medium text-gray-900 dark:text-white truncate">
                {item.title}
              </p>
              <p className="text-xs text-gray-500 dark:text-gray-400 mt-0.5">
                {getCheckName(item.check_id)}
              </p>
            </div>
            <SeverityBadge severity={item.severity} />
          </div>
          <div className="flex items-center gap-3 mt-2 text-xs text-gray-500 dark:text-gray-400">
            <span className="capitalize">
              {item.domain.replace(/_/g, " ")}
            </span>
            <span>~{item.estimated_fix_time_minutes}m</span>
          </div>
        </button>
      ))}
    </div>
  );
}
