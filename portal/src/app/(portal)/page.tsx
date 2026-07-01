"use client";

import { useEffect, useState } from "react";
import { apiGet } from "@/lib/api";

type Dora = {
  deployments: number;
  deployment_frequency_per_day: number;
  trails: number;
  compliance_rate: number;
  change_failure_rate: number;
};

function Card({ label, value, sub }: { label: string; value: string; sub?: string }) {
  return (
    <div className="rounded-xl border border-border bg-card p-5">
      <div className="text-xs uppercase tracking-wide text-muted-foreground">{label}</div>
      <div className="mt-2 text-2xl font-semibold">{value}</div>
      {sub && <div className="mt-1 text-xs text-muted-foreground">{sub}</div>}
    </div>
  );
}

export default function Overview() {
  const [flows, setFlows] = useState<number | null>(null);
  const [dora, setDora] = useState<Dora | null>(null);
  const [err, setErr] = useState("");

  useEffect(() => {
    apiGet<unknown[]>("/api/v1/flows").then((f) => setFlows(Array.isArray(f) ? f.length : 0)).catch(() => {});
    apiGet<Dora>("/api/v1/metrics/dora?days=30").then(setDora).catch((e) => setErr(String(e.message || e)));
  }, []);

  return (
    <div>
      <h1 className="text-xl font-semibold">Overview</h1>
      <p className="mt-1 text-sm text-muted-foreground">Real-time compliance status (last 30 days).</p>

      <div className="mt-6 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Card label="Flows" value={flows === null ? "…" : String(flows)} />
        <Card label="Deployments" value={dora ? String(dora.deployments) : "…"} sub={dora ? `${dora.deployment_frequency_per_day.toFixed(2)}/day` : undefined} />
        <Card label="Trails" value={dora ? String(dora.trails) : "…"} />
        <Card
          label="Compliance rate"
          value={dora ? `${Math.round(dora.compliance_rate * 100)}%` : "…"}
          sub={dora ? `change-failure ${Math.round(dora.change_failure_rate * 100)}%` : undefined}
        />
      </div>

      {err && <p className="mt-4 text-sm text-red-400">{err}</p>}
    </div>
  );
}
