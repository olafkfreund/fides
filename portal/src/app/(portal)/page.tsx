"use client";

import { useEffect, useState } from "react";
import { Package, ShieldCheck, AlertTriangle, Bot, CheckCircle2 } from "lucide-react";
import { apiGet } from "@/lib/api";

type Dora = {
  deployments: number;
  deployment_frequency_per_day: number;
  trails: number;
  compliance_rate: number;
  change_failure_rate: number;
};
type Env = { id: string; name: string; type: string };
type Att = { id: string; name: string; type_name: string; is_compliant: boolean; created_at?: string };

function Card({ label, value, sub, icon: Ic, iconClass }: { label: string; value: string; sub?: string; icon: React.ComponentType<{ className?: string }>; iconClass?: string }) {
  return (
    <div className="rounded-xl border border-border bg-card p-5">
      <div className="flex items-start justify-between">
        <div className="text-xs uppercase tracking-wide text-muted-foreground">{label}</div>
        <span className={`flex size-8 items-center justify-center rounded-lg bg-primary/10 ${iconClass || "text-primary"}`}><Ic className="size-4" /></span>
      </div>
      <div className="mt-2 text-2xl font-semibold">{value}</div>
      {sub && <div className="mt-1 text-xs text-muted-foreground">{sub}</div>}
    </div>
  );
}

export default function Overview() {
  const [dora, setDora] = useState<Dora | null>(null);
  const [artifacts, setArtifacts] = useState<number | null>(null);
  const [aiCount, setAiCount] = useState<number | null>(null);
  const [envs, setEnvs] = useState<Env[]>([]);
  const [atts, setAtts] = useState<Att[]>([]);
  const [err, setErr] = useState("");

  useEffect(() => {
    apiGet<Dora>("/api/v1/metrics/dora?days=30").then(setDora).catch((e) => setErr(String(e.message || e)));
    apiGet<unknown[]>("/api/v1/search/artifacts").then((a) => setArtifacts(Array.isArray(a) ? a.length : 0)).catch(() => {});
    apiGet<unknown[]>("/api/v1/ai-assessments").then((a) => setAiCount(Array.isArray(a) ? a.length : 0)).catch(() => {});
    apiGet<Env[]>("/api/v1/environments").then((e) => setEnvs(e || [])).catch(() => {});
    apiGet<Att[]>("/api/v1/search/attestations").then((a) => setAtts(a || [])).catch(() => {});
  }, []);

  const alerts = atts.filter((a) => !a.is_compliant).length;
  const trail = atts.slice(0, 12);

  return (
    <div>
      <h1 className="text-xl font-semibold">Dashboard</h1>
      <p className="mt-1 text-sm text-muted-foreground">Real-time compliance status of software components.</p>

      <div className="mt-6 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Card label="Tracked Artifacts" value={artifacts === null ? "…" : String(artifacts)} sub="Build artifacts tracked" icon={Package} />
        <Card label="Compliance Pass" value={dora ? `${Math.round(dora.compliance_rate * 100)}%` : "…"} sub="Artifacts passing JQ gates" icon={ShieldCheck} iconClass="text-green-400" />
        <Card label="Active Alerts" value={String(alerts)} sub="Non-compliant attestations" icon={AlertTriangle} iconClass={alerts > 0 ? "text-red-400" : "text-muted-foreground"} />
        <Card label="AI Evaluations" value={aiCount === null ? "…" : String(aiCount)} sub="LLM compliance reports" icon={Bot} />
      </div>

      <div className="mt-6 grid grid-cols-1 gap-5 lg:grid-cols-2">
        <div className="rounded-xl border border-border bg-card p-5">
          <h2 className="mb-3 text-xs font-semibold uppercase tracking-wide text-muted-foreground">Workload Environments</h2>
          {envs.length ? (
            <div className="flex flex-col gap-2">
              {envs.map((e) => (
                <div key={e.id} className="flex items-center justify-between rounded-md border border-border px-3 py-2 text-sm">
                  <span className="font-mono">{e.name}</span>
                  <span className="flex items-center gap-2">
                    <span className="rounded bg-muted px-2 py-0.5 text-xs text-muted-foreground">{e.type}</span>
                    <span className="rounded bg-green-500/15 px-2 py-0.5 text-xs font-medium text-green-400">SECURE</span>
                  </span>
                </div>
              ))}
            </div>
          ) : <p className="text-sm text-muted-foreground">No environments.</p>}
        </div>

        <div className="rounded-xl border border-border bg-card p-5">
          <h2 className="mb-3 text-xs font-semibold uppercase tracking-wide text-muted-foreground">Audit Log Trail</h2>
          {trail.length ? (
            <div className="flex flex-col gap-2">
              {trail.map((a) => (
                <div key={a.id} className="flex items-start gap-2 border-t border-border pt-2 text-sm first:border-t-0 first:pt-0">
                  <CheckCircle2 className={`mt-0.5 size-4 shrink-0 ${a.is_compliant ? "text-green-400" : "text-red-400"}`} />
                  <div className="min-w-0 flex-1">
                    <div className="truncate font-mono">{a.name} <span className="text-muted-foreground">· {a.type_name}</span></div>
                    <div className="text-xs text-muted-foreground">{(a.created_at || "").replace("T", " ").slice(0, 19)}</div>
                  </div>
                  <span className={`text-xs font-medium ${a.is_compliant ? "text-green-400" : "text-red-400"}`}>{a.is_compliant ? "pass" : "fail"}</span>
                </div>
              ))}
            </div>
          ) : <p className="text-sm text-muted-foreground">No recent attestations.</p>}
        </div>
      </div>

      {err && <p className="mt-4 text-sm text-red-400">{err}</p>}
    </div>
  );
}
