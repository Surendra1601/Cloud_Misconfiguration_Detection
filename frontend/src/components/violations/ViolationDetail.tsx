import type { Violation } from "@/types";
import {
  SeverityBadge,
  StatusBadge,
} from "@/components/shared";
import { getCheckName } from "@/constants/checkNames";

interface Props {
  violation: Violation;
  onClose: () => void;
}

function ComplianceSection({
  label,
  controls,
}: {
  label: string;
  controls: string[];
}) {
  if (controls.length === 0) return null;
  return (
    <div>
      <p className="text-xs font-medium text-gray-500 dark:text-gray-400">
        {label}
      </p>
      <div className="flex flex-wrap gap-1 mt-1">
        {controls.map((c) => (
          <span
            key={c}
            className="inline-block px-1.5 py-0.5 bg-gray-100 dark:bg-gray-700 text-xs rounded text-gray-700 dark:text-gray-300"
          >
            {c}
          </span>
        ))}
      </div>
    </div>
  );
}

export default function ViolationDetail({
  violation,
  onClose,
}: Props) {
  const v = violation;
  const comp = v.compliance ?? {} as {
    cis_aws?: string[];
    nist_800_53?: string[];
    pci_dss?: string[];
    hipaa?: string[];
    soc2?: string[];
  };
  const cisAws      = comp.cis_aws      ?? [];
  const nist        = comp.nist_800_53  ?? [];
  const pci         = comp.pci_dss      ?? [];
  const hipaa       = comp.hipaa        ?? [];
  const soc2        = comp.soc2         ?? [];

  return (
    <div className="fixed inset-0 z-40 flex justify-end">
      <div
        className="fixed inset-0 bg-black/30"
        onClick={onClose}
      />
      <div className="relative w-full max-w-md bg-white dark:bg-gray-800 shadow-xl overflow-y-auto">
        <div className="sticky top-0 bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700 px-6 py-4 flex items-center justify-between">
          <h3 className="text-sm font-semibold text-gray-900 dark:text-white">
            Violation Detail
          </h3>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-200"
          >
            <svg
              className="w-5 h-5"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M6 18L18 6M6 6l12 12"
              />
            </svg>
          </button>
        </div>

        <div className="px-6 py-5 space-y-5">
          {/* Issue */}
          <div>
            <p className="text-xs text-gray-500 dark:text-gray-400">
              Issue
            </p>
            <p className="text-sm font-medium text-gray-900 dark:text-white mt-0.5">
              {getCheckName(v.check_id)}
            </p>
            <p className="text-[10px] font-mono text-gray-400 dark:text-gray-500 mt-0.5">
              {v.check_id}
            </p>
          </div>

          {/* Status + Severity */}
          <div className="flex gap-3">
            <div>
              <p className="text-xs text-gray-500 dark:text-gray-400 mb-1">
                Status
              </p>
              <StatusBadge status={v.status} />
            </div>
            <div>
              <p className="text-xs text-gray-500 dark:text-gray-400 mb-1">
                Severity
              </p>
              <SeverityBadge severity={v.severity} />
            </div>
          </div>

          {/* Domain */}
          <div>
            <p className="text-xs text-gray-500 dark:text-gray-400">
              Domain
            </p>
            <p className="text-sm text-gray-900 dark:text-white mt-0.5 capitalize">
              {v.domain.replace(/_/g, " ")}
            </p>
          </div>

          {/* Resource */}
          <div>
            <p className="text-xs text-gray-500 dark:text-gray-400">
              Resource
            </p>
            <p className="text-sm font-mono text-gray-900 dark:text-white mt-0.5 break-all">
              {v.resource || "N/A"}
            </p>
          </div>

          {/* Reason */}
          <div>
            <p className="text-xs text-gray-500 dark:text-gray-400">
              Reason
            </p>
            <p className="text-sm text-gray-700 dark:text-gray-300 mt-0.5">
              {v.reason || "No reason provided"}
            </p>
          </div>

          {/* Remediation ID */}
          {v.remediation_id && (
            <div>
              <p className="text-xs text-gray-500 dark:text-gray-400">
                Remediation ID
              </p>
              <p className="text-sm font-mono text-primary-600 dark:text-primary-400 mt-0.5">
                {v.remediation_id}
              </p>
            </div>
          )}

          {/* Compliance Mappings */}
          <div className="border-t border-gray-200 dark:border-gray-700 pt-4">
            <h4 className="text-xs font-semibold text-gray-900 dark:text-white mb-3 uppercase tracking-wider">
              Compliance Mappings
            </h4>
            <div className="space-y-3">
              <ComplianceSection
                label="CIS AWS"
                controls={cisAws}
              />
              <ComplianceSection
                label="NIST 800-53"
                controls={nist}
              />
              <ComplianceSection
                label="PCI DSS"
                controls={pci}
              />
              <ComplianceSection
                label="HIPAA"
                controls={hipaa}
              />
              <ComplianceSection
                label="SOC 2"
                controls={soc2}
              />
              {!cisAws.length &&
                !nist.length &&
                !pci.length &&
                !hipaa.length &&
                !soc2.length && (
                  <p className="text-xs text-gray-400">
                    No compliance mappings
                  </p>
                )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
