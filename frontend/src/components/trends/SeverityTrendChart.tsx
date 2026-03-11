import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from "recharts";
import type { TrendPoint } from "@/hooks";

interface Props {
  data: TrendPoint[];
}

export default function SeverityTrendChart({
  data,
}: Props) {
  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
      <h3 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-4">
        Violations by Severity
      </h3>
      <div className="h-72">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data}>
            <CartesianGrid
              strokeDasharray="3 3"
              stroke="#e5e7eb"
            />
            <XAxis
              dataKey="date"
              tick={{ fontSize: 11 }}
              axisLine={false}
              tickLine={false}
            />
            <YAxis
              allowDecimals={false}
              tick={{ fontSize: 11 }}
              axisLine={false}
              tickLine={false}
            />
            <Tooltip />
            <Legend />
            <Area
              type="monotone"
              dataKey="critical"
              stackId="1"
              stroke="#dc2626"
              fill="#dc2626"
              fillOpacity={0.6}
              name="Critical"
            />
            <Area
              type="monotone"
              dataKey="high"
              stackId="1"
              stroke="#f97316"
              fill="#f97316"
              fillOpacity={0.6}
              name="High"
            />
            <Area
              type="monotone"
              dataKey="medium"
              stackId="1"
              stroke="#eab308"
              fill="#eab308"
              fillOpacity={0.6}
              name="Medium"
            />
            <Area
              type="monotone"
              dataKey="low"
              stackId="1"
              stroke="#22c55e"
              fill="#22c55e"
              fillOpacity={0.6}
              name="Low"
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
