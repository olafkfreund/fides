"use client";

import { useEffect, useRef, useState } from "react";
import {
  ResponsiveContainer, LineChart, Line, AreaChart, Area, BarChart, Bar,
  PieChart, Pie, Cell, XAxis, YAxis, Tooltip, CartesianGrid, Legend,
} from "recharts";
import { apiGet } from "@/lib/api";

type Metrics = {
  total_requests: number;
  total_errors: number;
  error_rate: number;
  average_latency_ms: number;
  uptime_seconds: number;
  db_connections: { open: number; in_use: number; idle: number };
  memory_allocated_mb: number;
  goroutines: number;
};
type Point = { t: string; requests: number; latency: number; memory: number };

const GOLD = "#edb200";
const GREEN = "#22c55e";
const RED = "#ef4444";
const BLUE = "#3b82f6";
const MUTED = "#a1a1a1";

const panel = "rounded-xl border border-border bg-card p-5";
const tooltipStyle = { background: "#171717", border: "1px solid #262626", borderRadius: 8, fontSize: 12, color: "#fafafa" };

function KPI({ label, value, sub, color }: { label: string; value: string; sub?: string; color?: string }) {
  return (
    <div className={panel}>
      <div className="text-xs uppercase tracking-wide text-muted-foreground">{label}</div>
      <div className="mt-2 text-2xl font-semibold" style={color ? { color } : undefined}>{value}</div>
      {sub && <div className="mt-1 text-xs text-muted-foreground">{sub}</div>}
    </div>
  );
}

function fmtUptime(s: number) {
  const h = Math.floor(s / 3600), mn = Math.floor((s % 3600) / 60);
  return h > 0 ? `${h}h ${mn}m` : `${mn}m ${s % 60}s`;
}

const PALETTE = ["#edb200", "#3b82f6", "#22c55e", "#a855f7", "#ef4444", "#06b6d4"];
type FreqRow = { environment: string; week: string; deployments: number };

export default function Telemetry() {
  const [m, setM] = useState<Metrics | null>(null);
  const [series, setSeries] = useState<Point[]>([]);
  const [freq, setFreq] = useState<FreqRow[]>([]);
  const [err, setErr] = useState("");
  const timer = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    apiGet<FreqRow[]>("/api/v1/metrics/deployment-frequency?weeks=12").then((f) => setFreq(f || [])).catch(() => {});
  }, []);

  useEffect(() => {
    const poll = () => apiGet<Metrics>("/api/v1/telemetry/metrics").then((d) => {
      setM(d);
      const now = new Date();
      const t = `${String(now.getHours()).padStart(2, "0")}:${String(now.getMinutes()).padStart(2, "0")}:${String(now.getSeconds()).padStart(2, "0")}`;
      setSeries((prev) => [...prev, { t, requests: d.total_requests, latency: Math.round(d.average_latency_ms * 100) / 100, memory: Math.round(d.memory_allocated_mb * 10) / 10 }].slice(-24));
    }).catch((e) => setErr(String(e.message || e)));
    poll();
    timer.current = setInterval(poll, 3000);
    return () => { if (timer.current) clearInterval(timer.current); };
  }, []);

  const dbData = m ? [
    { name: "In use", value: m.db_connections.in_use, fill: GOLD },
    { name: "Idle", value: m.db_connections.idle, fill: BLUE },
  ] : [];
  const reqSplit = m ? [
    { name: "Success", value: Math.max(0, m.total_requests - m.total_errors), fill: GREEN },
    { name: "Errors", value: m.total_errors, fill: RED },
  ] : [];

  const envNames = [...new Set(freq.map((f) => f.environment))];
  const weeks = [...new Set(freq.map((f) => f.week))].sort();
  const freqData = weeks.map((week) => {
    const row: Record<string, string | number> = { week };
    envNames.forEach((env) => { row[env] = freq.find((f) => f.week === week && f.environment === env)?.deployments ?? 0; });
    return row;
  });

  return (
    <div>
      <h1 className="text-xl font-semibold">Telemetry &amp; OTel</h1>
      <p className="mt-1 text-sm text-muted-foreground">Live API backend metrics (updates every 3s).</p>

      <div className="mt-6 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <KPI label="Total Requests" value={m ? m.total_requests.toLocaleString() : "…"} sub={m ? `${m.goroutines} goroutines` : undefined} />
        <KPI label="Error Rate" value={m ? `${m.error_rate.toFixed(2)}%` : "…"} sub={m ? `${m.total_errors} errors` : undefined} color={m && m.error_rate > 1 ? RED : GREEN} />
        <KPI label="Avg Latency" value={m ? `${m.average_latency_ms.toFixed(1)} ms` : "…"} color={GOLD} />
        <KPI label="Uptime" value={m ? fmtUptime(m.uptime_seconds) : "…"} sub={m ? `${m.memory_allocated_mb.toFixed(1)} MB heap` : undefined} />
      </div>

      {freqData.length > 0 && (
        <div className={`${panel} mt-6`}>
          <h2 className="mb-3 text-xs font-semibold uppercase tracking-wide text-muted-foreground">Deployment Frequency — weekly, per environment (last 12 weeks)</h2>
          <ResponsiveContainer width="100%" height={260}>
            <BarChart data={freqData} margin={{ left: -10, right: 8, top: 5 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#262626" />
              <XAxis dataKey="week" tick={{ fill: MUTED, fontSize: 11 }} stroke="#262626" />
              <YAxis allowDecimals={false} tick={{ fill: MUTED, fontSize: 11 }} stroke="#262626" />
              <Tooltip contentStyle={tooltipStyle} cursor={{ fill: "#ffffff08" }} />
              <Legend wrapperStyle={{ fontSize: 12 }} />
              {envNames.map((env, i) => <Bar key={env} dataKey={env} stackId="a" fill={PALETTE[i % PALETTE.length]} radius={i === envNames.length - 1 ? [4, 4, 0, 0] : undefined} />)}
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}

      <div className="mt-6 grid grid-cols-1 gap-5 lg:grid-cols-2">
        <div className={panel}>
          <h2 className="mb-3 text-xs font-semibold uppercase tracking-wide text-muted-foreground">Requests &amp; Latency (live)</h2>
          <ResponsiveContainer width="100%" height={220}>
            <LineChart data={series} margin={{ left: -10, right: 8, top: 5 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#262626" />
              <XAxis dataKey="t" tick={{ fill: MUTED, fontSize: 11 }} stroke="#262626" />
              <YAxis yAxisId="l" tick={{ fill: MUTED, fontSize: 11 }} stroke="#262626" />
              <YAxis yAxisId="r" orientation="right" tick={{ fill: MUTED, fontSize: 11 }} stroke="#262626" />
              <Tooltip contentStyle={tooltipStyle} />
              <Line yAxisId="l" type="monotone" dataKey="requests" stroke={GOLD} strokeWidth={2} dot={false} name="requests" />
              <Line yAxisId="r" type="monotone" dataKey="latency" stroke={BLUE} strokeWidth={2} dot={false} name="latency ms" />
            </LineChart>
          </ResponsiveContainer>
        </div>

        <div className={panel}>
          <h2 className="mb-3 text-xs font-semibold uppercase tracking-wide text-muted-foreground">Heap Memory (live, MB)</h2>
          <ResponsiveContainer width="100%" height={220}>
            <AreaChart data={series} margin={{ left: -10, right: 8, top: 5 }}>
              <defs>
                <linearGradient id="mem" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor={GOLD} stopOpacity={0.5} />
                  <stop offset="95%" stopColor={GOLD} stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#262626" />
              <XAxis dataKey="t" tick={{ fill: MUTED, fontSize: 11 }} stroke="#262626" />
              <YAxis tick={{ fill: MUTED, fontSize: 11 }} stroke="#262626" />
              <Tooltip contentStyle={tooltipStyle} />
              <Area type="monotone" dataKey="memory" stroke={GOLD} strokeWidth={2} fill="url(#mem)" name="heap MB" />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        <div className={panel}>
          <h2 className="mb-3 text-xs font-semibold uppercase tracking-wide text-muted-foreground">DB Connections</h2>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={dbData} margin={{ left: -10, right: 8, top: 5 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#262626" />
              <XAxis dataKey="name" tick={{ fill: MUTED, fontSize: 11 }} stroke="#262626" />
              <YAxis allowDecimals={false} tick={{ fill: MUTED, fontSize: 11 }} stroke="#262626" />
              <Tooltip contentStyle={tooltipStyle} cursor={{ fill: "#ffffff08" }} />
              <Bar dataKey="value" radius={[6, 6, 0, 0]}>
                {dbData.map((d, i) => <Cell key={i} fill={d.fill} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className={panel}>
          <h2 className="mb-3 text-xs font-semibold uppercase tracking-wide text-muted-foreground">Request Outcomes</h2>
          <ResponsiveContainer width="100%" height={220}>
            <PieChart>
              <Pie data={reqSplit} dataKey="value" nameKey="name" innerRadius={55} outerRadius={85} paddingAngle={2}>
                {reqSplit.map((d, i) => <Cell key={i} fill={d.fill} />)}
              </Pie>
              <Tooltip contentStyle={tooltipStyle} />
            </PieChart>
          </ResponsiveContainer>
          <div className="mt-2 flex justify-center gap-4 text-xs text-muted-foreground">
            <span className="flex items-center gap-1"><span className="size-2 rounded-full" style={{ background: GREEN }} /> Success</span>
            <span className="flex items-center gap-1"><span className="size-2 rounded-full" style={{ background: RED }} /> Errors</span>
          </div>
        </div>
      </div>

      {err && <p className="mt-4 text-sm text-red-400">{err}</p>}
    </div>
  );
}
