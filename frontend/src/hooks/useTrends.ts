import { useMemo } from "react";
import { useDriftAlerts } from "./useDriftAlerts";

export type Period = "7d" | "30d" | "90d";

export interface TrendPoint {
  date: string;
  violations: number;
  resolutions: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

function daysAgo(days: number): Date {
  const d = new Date();
  d.setDate(d.getDate() - days);
  d.setHours(0, 0, 0, 0);
  return d;
}

function formatDate(d: Date): string {
  const m = String(d.getMonth() + 1).padStart(2, "0");
  const day = String(d.getDate()).padStart(2, "0");
  return `${m}/${day}`;
}

const PERIOD_DAYS: Record<Period, number> = {
  "7d": 7,
  "30d": 30,
  "90d": 90,
};

export function useTrends(period: Period) {
  const days = PERIOD_DAYS[period];
  const { data, isLoading, error } = useDriftAlerts({
    limit: 1000,
  });

  const trends = useMemo(() => {
    if (!data?.alerts) return [];

    const cutoff = daysAgo(days);
    const buckets = new Map<string, TrendPoint>();

    // Initialize all date buckets
    for (let i = days - 1; i >= 0; i--) {
      const d = new Date();
      d.setDate(d.getDate() - i);
      d.setHours(0, 0, 0, 0);
      const key = d.toISOString().slice(0, 10);
      buckets.set(key, {
        date: formatDate(d),
        violations: 0,
        resolutions: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
      });
    }

    // Populate from alerts
    for (const alert of data.alerts) {
      const ts = new Date(alert.timestamp);
      if (ts < cutoff) continue;
      const key = ts.toISOString().slice(0, 10);
      const bucket = buckets.get(key);
      if (!bucket) continue;

      if (alert.type === "new_violation") {
        bucket.violations++;
        // Severity only counts for new violations —
        // resolving a critical issue should NOT add to critical count
        const sev = alert.severity?.toLowerCase();
        if (sev === "critical") bucket.critical++;
        else if (sev === "high") bucket.high++;
        else if (sev === "medium") bucket.medium++;
        else if (sev === "low") bucket.low++;
      } else if (alert.type === "resolution") {
        bucket.resolutions++;
      }
    }

    return Array.from(buckets.values());
  }, [data, days]);

  return { trends, isLoading, error };
}
