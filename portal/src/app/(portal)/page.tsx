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

type Env = { id: string; name: string; type: string };
type Att = { id: string; name: string; type_name: string; is_compliant: boolean; created_at?: string };

export default function Overview() {
  const [flows, setFlows] = useState<number | null>(null);
  const [dora, setDora] = useState<Dora | null>(null);
  const [envs, setEnvs] = useState<Env[]>([]);
  const [trail, setTrail] = useState<Att[]>([]);
  const [err, setErr] = useState("");

  useEffect(() => {
    apiGet<unknown[]>("/api/v1/flows").then((f) => setFlows(Array.isArray(f) ? f.length : 0)).catch(() => {});
    apiGet<Dora>("/api/v1/metrics/dora?days=30").then(setDora).catch((e) => setErr(String(e.message || e)));
    apiGet<Env[]>("/api/v1/environments").then((e) => setEnvs(e || [])).catch(() => {});
    apiGet<Att[]>("/api/v1/search/attestations").then((a) => setTrail((a || []).slice(0, 12))).catch(() => {});
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

      <div className="mt-6 grid grid-cols-1 gap-5 lg:grid-cols-2">
        <div className="rounded-xl border border-border bg-card p-5">
          <h2 className="mb-3 text-xs font-semibold uppercase tracking-wide text-muted-foreground">Workload Environments</h2>
          {envs.length ? (
            <div className="flex flex-col gap-2">
              {envs.map((e) => (
                <div key={e.id} className="flex items-center justify-between rounded-md border border-border px-3 py-2 text-sm">
                  <span className="font-mono">{e.name}</span>
                  <span className="rounded bg-muted px-2 py-0.5 text-xs text-muted-foreground">{e.type}</span>
                </div>
              ))}
            </div>
          ) : <p className="text-sm text-muted-foreground">No environments.</p>}
        </div>

        <div className="rounded-xl border border-border bg-card p-5">
          <h2 className="mb-3 text-xs font-semibold uppercase tracking-wide text-muted-foreground">Audit Log Trail</h2>
          {trail.length ? (
            <table className="w-full text-left text-xs font-mono">
              <thead className="text-muted-foreground"><tr><th className="py-1">Attestation</th><th>Type</th><th>Status</th></tr></thead>
              <tbody>{trail.map((a) => (
                <tr key={a.id} className="border-t border-border">
                  <td className="py-1">{a.name}</td>
                  <td>{a.type_name}</td>
                  <td className={a.is_compliant ? "text-green-400" : "text-red-400"}>{a.is_compliant ? "pass" : "fail"}</td>
                </tr>
              ))}</tbody>
            </table>
          ) : <p className="text-sm text-muted-foreground">No recent attestations.</p>}
        </div>
      </div>

      {err && <p className="mt-4 text-sm text-red-400">{err}</p>}
    </div>
  );
}
