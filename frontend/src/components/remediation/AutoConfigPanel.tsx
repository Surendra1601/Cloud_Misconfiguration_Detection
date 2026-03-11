import {
  useRemediationConfigs,
  useSaveConfig,
} from "@/hooks";

export default function AutoConfigPanel() {
  const { data, isLoading, error } =
    useRemediationConfigs();
  const saveMutation = useSaveConfig();

  const handleToggle = (
    checkId: string,
    currentEnabled: boolean,
  ) => {
    saveMutation.mutate({
      check_id: checkId,
      enabled: !currentEnabled,
    });
  };

  if (isLoading) {
    return (
      <div className="animate-pulse space-y-2">
        {Array.from({ length: 3 }).map((_, i) => (
          <div
            key={i}
            className="h-14 bg-gray-100 dark:bg-gray-700 rounded"
          />
        ))}
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded p-3">
        <p className="text-sm text-red-700 dark:text-red-400">
          Failed to load auto-remediation configs.
        </p>
      </div>
    );
  }

  if (!data || data.configs.length === 0) {
    return (
      <p className="text-sm text-gray-500 dark:text-gray-400">
        No auto-remediation configs configured.
      </p>
    );
  }

  return (
    <div className="space-y-2">
      {data.configs.map((config) => (
        <div
          key={`${config.account_id}-${config.check_id}`}
          className="flex items-center justify-between border border-gray-200 dark:border-gray-700 rounded-lg p-4"
        >
          <div>
            <p className="text-sm font-medium text-gray-900 dark:text-white font-mono">
              {config.check_id}
            </p>
            <div className="flex gap-3 mt-1 text-xs text-gray-500 dark:text-gray-400">
              <span>
                Rollback: {config.rollback_window_minutes}m
              </span>
              <span>
                Notify:{" "}
                {config.notify_on_action ? "Yes" : "No"}
              </span>
              {config.approved_by && (
                <span>
                  Approved by: {config.approved_by}
                </span>
              )}
            </div>
          </div>

          <button
            onClick={() =>
              handleToggle(
                config.check_id,
                config.enabled,
              )
            }
            disabled={saveMutation.isPending}
            className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
              config.enabled
                ? "bg-primary-600"
                : "bg-gray-300 dark:bg-gray-600"
            }`}
          >
            <span
              className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                config.enabled
                  ? "translate-x-6"
                  : "translate-x-1"
              }`}
            />
          </button>
        </div>
      ))}
    </div>
  );
}
