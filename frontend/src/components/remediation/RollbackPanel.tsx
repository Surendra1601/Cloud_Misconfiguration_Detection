import { useState } from "react";
import { useRollbackRemediation } from "@/hooks";

interface Props {
  remediationId: string;
}

export default function RollbackPanel({
  remediationId,
}: Props) {
  const [actionId, setActionId] = useState("");
  const mutation = useRollbackRemediation();

  const handleRollback = () => {
    if (!actionId.trim()) return;
    mutation.mutate({
      id: remediationId,
      request: { action_id: actionId.trim() },
    });
  };

  return (
    <div className="border border-gray-200 dark:border-gray-700 rounded-lg p-4">
      <h4 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">
        Rollback
      </h4>

      <div className="space-y-3">
        <div>
          <label className="block text-xs font-medium text-gray-500 dark:text-gray-400 mb-1">
            Action ID
          </label>
          <input
            type="text"
            value={actionId}
            onChange={(e) => setActionId(e.target.value)}
            placeholder="Action ID from execution"
            className="w-full rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-sm text-gray-900 dark:text-gray-100 px-3 py-2 focus:outline-none focus:ring-2 focus:ring-primary-500"
          />
        </div>

        <button
          onClick={handleRollback}
          disabled={
            !actionId.trim() || mutation.isPending
          }
          className="w-full px-4 py-2 text-sm font-medium rounded-md text-white bg-orange-600 hover:bg-orange-700 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
        >
          {mutation.isPending
            ? "Rolling back..."
            : "Rollback"}
        </button>
      </div>

      {mutation.isSuccess && mutation.data && (
        <div className="mt-3 bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded p-3">
          <p className="text-sm text-green-700 dark:text-green-400 font-medium">
            {mutation.data.status}: {mutation.data.message}
          </p>
        </div>
      )}

      {mutation.isError && (
        <div className="mt-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded p-3">
          <p className="text-sm text-red-700 dark:text-red-400">
            {(
              mutation.error as {
                message?: string;
              }
            ).message ?? "Rollback failed"}
          </p>
        </div>
      )}
    </div>
  );
}
