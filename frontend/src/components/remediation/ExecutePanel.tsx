import { useState } from "react";
import { useExecuteRemediation } from "@/hooks";

interface Props {
  remediationId: string;
}

export default function ExecutePanel({
  remediationId,
}: Props) {
  const [resourceArn, setResourceArn] = useState("");
  const [confirm, setConfirm] = useState(false);
  const mutation = useExecuteRemediation();

  const handleExecute = () => {
    if (!resourceArn.trim() || !confirm) return;
    mutation.mutate({
      id: remediationId,
      request: {
        resource_arn: resourceArn.trim(),
        confirm: true,
      },
    });
  };

  return (
    <div className="border border-gray-200 dark:border-gray-700 rounded-lg p-4">
      <h4 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">
        One-Click Execute
      </h4>

      <div className="space-y-3">
        <div>
          <label className="block text-xs font-medium text-gray-500 dark:text-gray-400 mb-1">
            Resource ARN
          </label>
          <input
            type="text"
            value={resourceArn}
            onChange={(e) =>
              setResourceArn(e.target.value)
            }
            placeholder="arn:aws:s3:::my-bucket"
            className="w-full rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-sm text-gray-900 dark:text-gray-100 px-3 py-2 focus:outline-none focus:ring-2 focus:ring-primary-500"
          />
        </div>

        <label className="flex items-center gap-2 text-sm text-gray-700 dark:text-gray-300">
          <input
            type="checkbox"
            checked={confirm}
            onChange={(e) => setConfirm(e.target.checked)}
            className="rounded border-gray-300 dark:border-gray-600"
          />
          I confirm this remediation action
        </label>

        <button
          onClick={handleExecute}
          disabled={
            !resourceArn.trim() ||
            !confirm ||
            mutation.isPending
          }
          className="w-full px-4 py-2 text-sm font-medium rounded-md text-white bg-primary-600 hover:bg-primary-700 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
        >
          {mutation.isPending
            ? "Executing..."
            : "Execute Remediation"}
        </button>
      </div>

      {mutation.isSuccess && mutation.data && (
        <div className="mt-3 bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded p-3">
          <p className="text-sm text-green-700 dark:text-green-400 font-medium">
            Status: {mutation.data.status}
          </p>
          <p className="text-xs text-green-600 dark:text-green-500 mt-1 font-mono">
            Action ID: {mutation.data.action_id}
          </p>
          {mutation.data.rollback_available_until && (
            <p className="text-xs text-green-600 dark:text-green-500 mt-0.5">
              Rollback available until:{" "}
              {new Date(
                mutation.data.rollback_available_until,
              ).toLocaleString()}
            </p>
          )}
        </div>
      )}

      {mutation.isError && (
        <div className="mt-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded p-3">
          <p className="text-sm text-red-700 dark:text-red-400">
            {(
              mutation.error as {
                message?: string;
              }
            ).message ?? "Execution failed"}
          </p>
        </div>
      )}
    </div>
  );
}
