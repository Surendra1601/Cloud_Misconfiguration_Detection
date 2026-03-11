import {
  LineChart,
  Line,
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

export default function TrendLineChart({ data }: Props) {
  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
      <h3 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-4">
        Violations vs Resolutions
      </h3>
      <div className="h-72">
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={data}>
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
            <Line
              type="monotone"
              dataKey="violations"
              stroke="#dc2626"
              strokeWidth={2}
              dot={false}
              name="New Violations"
            />
            <Line
              type="monotone"
              dataKey="resolutions"
              stroke="#22c55e"
              strokeWidth={2}
              dot={false}
              name="Resolutions"
            />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
