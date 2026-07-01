"use client";

import { useEffect, useState } from "react";
import { apiGet } from "@/lib/api";

export default function Telemetry() {
  const [metrics, setMetrics] = useState<Record<string, unknown> | null>(null);
  const [err, setErr] = useState("");

  const load = () =>
    apiGet<Record<string, unknown>>("/api/v1/telemetry/metrics")
      .then(setMetrics)
      .catch((e) => setErr(String(e.message || e)));

  useEffect(() => { load(); }, []);

  const entries = metrics ? Object.entries(metrics) : [];

  return (
    <div className="max-w-3xl">
      <h1 className="text-xl font-semibold">Telemetry</h1>
      <p className="mt-1 text-sm text-neutral-500">API backend metrics (OpenTelemetry / Prometheus).</p>

      <div className="mt-6 rounded-xl border border-neutral-800 bg-neutral-900 p-5">
        <div className="mb-3"><button onClick={load} className="rounded-md border border-neutral-700 px-4 py-2 text-sm">Refresh</button></div>
        {entries.length ? (
          <table className="w-full text-left text-sm font-mono">
            <tbody>{entries.map(([k, v]) => (
              <tr key={k} className="border-t border-neutral-800">
                <td className="py-2 text-neutral-400">{k}</td>
                <td className="py-2 text-neutral-200">{typeof v === "object" ? JSON.stringify(v) : String(v)}</td>
              </tr>
            ))}</tbody>
          </table>
        ) : <p className="text-sm text-neutral-500">{metrics ? "No metrics." : "Loading…"}</p>}
      </div>
      {err && <p className="mt-4 text-sm text-red-400">{err}</p>}
    </div>
  );
}
