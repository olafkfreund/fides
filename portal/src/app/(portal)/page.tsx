"use client";

import { useEffect, useRef, useState } from "react";
import { Package, ShieldCheck, CheckCircle2, Zap } from "lucide-react";
import { apiGet } from "@/lib/api";
import { Panel, SectionLabel, Ring, StatTile } from "@/components/dash";

// Live snapshot from the console summary endpoint (counts + recent checks).
type Summary = {
  artifacts: number;
  checksTotal: number;
  checksLast24h: number;
  compliant: number;
  nonCompliant: number;
  compliancePct: number;
  aiEvaluations: number;
  recent: { name: string; kind: string; compliant: boolean; at: string }[];
};
type Env = { id: string; name: string; type: string; drifts?: string[]; shadowChanges?: string[] };
type Coverage = { controls: { control: string; coverage: number }[] };
type IntEvent = { event_type: string; status: string };

const num = (n: number | null | undefined) => (n == null ? "—" : n.toLocaleString());

const FAM_COLORS = ["#edb200", "#49AEDC", "#35C08A", "#F2823C", "#E5484D", "#A78BFA"];

// Coverage donut segmented by control-framework prefix (DORA / ISO / SOC2 …).
function CoverageDonut({ controls }: { controls: { control: string; coverage: number }[] }) {
  const size = 150, stroke = 14, r = size / 2 - stroke, c = 2 * Math.PI * r, gap = 4;
  const covered = controls.filter((x) => x.coverage > 0).length;
  const fam = new Map<string, number>();
  for (const x of controls) { const k = x.control.split(/[-.]/)[0] || "OTHER"; fam.set(k, (fam.get(k) || 0) + 1); }
  const keys = [...fam.keys()].sort((a, b) => fam.get(b)! - fam.get(a)!);
  const total = controls.length || 1;
  // Prefix-sum the offset purely (no render-scope reassignment — the Next 16
  // React Compiler forbids mutating a variable declared during render).
  const segs = keys.map((k, i) => {
    const frac = fam.get(k)! / total;
    const len = Math.max(0, frac * c - gap);
    const prev = keys.slice(0, i).reduce((sum, kk) => sum + (fam.get(kk)! / total) * c, 0);
    return { k, color: FAM_COLORS[i % FAM_COLORS.length], dash: `${len} ${c - len}`, off: -prev, count: fam.get(k)! };
  });
  return (
    <div className="flex flex-col items-center gap-4">
      <div className="relative" style={{ width: size, height: size }}>
        <svg width={size} height={size} className="-rotate-90">
          <circle cx={size / 2} cy={size / 2} r={r} fill="none" strokeWidth={stroke} className="stroke-muted" />
          {segs.map((seg) => (
            <circle key={seg.k} cx={size / 2} cy={size / 2} r={r} fill="none" strokeWidth={stroke} stroke={seg.color} strokeDasharray={seg.dash} strokeDashoffset={seg.off} />
          ))}
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="font-mono text-2xl font-bold tabular-nums">{covered}/{controls.length}</span>
          <span className="mt-0.5 text-[9px] uppercase tracking-[0.16em] text-muted-foreground">Covered</span>
        </div>
      </div>
      <div className="flex w-full flex-col gap-2">
        {segs.map((seg) => (
          <div key={seg.k} className="flex items-center gap-2.5 text-xs">
            <span className="size-2.5 shrink-0 rounded-sm" style={{ background: seg.color }} />
            <span className="font-mono text-muted-foreground">{seg.k}</span>
            <span className="ml-auto font-mono tabular-nums text-muted-foreground">{seg.count}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function Overview() {
  const [s, setS] = useState<Summary | null>(null);
  const [envs, setEnvs] = useState<Env[]>([]);
  const [cov, setCov] = useState<Coverage | null>(null);
  const [events, setEvents] = useState<IntEvent[]>([]);
  const [updated, setUpdated] = useState<string>("");
  const [live, setLive] = useState(true);
  const lastTop = useRef<string | null>(null);
  const [flashTop, setFlashTop] = useState(false);

  useEffect(() => {
    let stop = false;
    const tick = () => {
      apiGet<Summary>("/api/v1/console/summary").then((d) => {
        if (stop) return;
        setLive(true);
        const top = d.recent?.[0] ? d.recent[0].name + d.recent[0].at : null;
        if (top && lastTop.current !== null && top !== lastTop.current) { setFlashTop(true); setTimeout(() => setFlashTop(false), 1600); }
        lastTop.current = top;
        setS(d);
        setUpdated(new Date().toLocaleTimeString());
      }).catch(() => { if (!stop) setLive(false); });
      apiGet<Env[]>("/api/v1/environments").then((e) => !stop && setEnvs(e || [])).catch(() => {});
      apiGet<Coverage>("/api/v1/controls/coverage").then((c) => !stop && setCov(c)).catch(() => {});
      apiGet<IntEvent[]>("/api/v1/tenant/servicenow/events").then((e) => !stop && setEvents(e || [])).catch(() => {});
    };
    tick();
    const id = setInterval(tick, 5000);
    return () => { stop = true; clearInterval(id); };
  }, []);

  const secureEnvs = envs.filter((e) => !e.drifts?.length && !e.shadowChanges?.length).length;
  const pct = s?.compliancePct ?? 0;

  return (
    <div
      className="-m-4 p-4 sm:-m-6 sm:p-6"
      style={{
        backgroundImage:
          "linear-gradient(rgba(128,128,140,0.05) 1px,transparent 1px),linear-gradient(90deg,rgba(128,128,140,0.05) 1px,transparent 1px)",
        backgroundSize: "34px 34px",
      }}
    >
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="font-mono text-lg font-semibold uppercase tracking-[0.2em]">Assurance Console</h1>
          <p className="mt-1 text-sm text-muted-foreground">Live compliance &amp; provenance posture across every tracked artifact.</p>
        </div>
        <span className={`flex items-center gap-2 rounded-lg border border-border bg-card px-3 py-1.5 font-mono text-[11px] ${live ? "text-green-400" : "text-amber-400"}`}>
          <span className={`size-1.5 rounded-full ${live ? "bg-green-400" : "bg-amber-400"}`} />
          {live ? "Live" : "Offline"}<span className="text-muted-foreground">{updated && ` · ${updated}`}</span>
        </span>
      </div>

      {/* Row 1 — posture + coverage + environments */}
      <div className="mt-6 grid grid-cols-1 gap-4 lg:grid-cols-4">
        <Panel className="lg:col-span-2">
          <SectionLabel>Compliance Posture</SectionLabel>
          <div className="mt-4 flex flex-wrap items-center gap-6">
            <Ring value={pct / 100} size={190} stroke={13} color="#35C08A">
              <span className="font-mono text-[44px] font-bold leading-none tabular-nums">{s ? pct : "—"}<span className="text-xl text-muted-foreground">%</span></span>
              <span className="mt-1 font-mono text-[11px] uppercase tracking-[0.22em] text-green-400">Passing</span>
            </Ring>
            <div className="min-w-[220px] flex-1">
              <h3 className="text-lg font-semibold">{s && s.nonCompliant > 0 ? `${s.nonCompliant} need attention` : "All environments verified & sealed"}</h3>
              <p className="mt-1 text-sm text-muted-foreground">Every tracked artifact carries a signed attestation chain; the tamper-evident ledger is intact.</p>
              <div className="mt-4 grid grid-cols-3 gap-2.5">
                {[
                  { n: num(s?.artifacts), t: "Artifacts", cls: "" },
                  { n: num(s?.nonCompliant), t: "Alerts", cls: s && s.nonCompliant > 0 ? "text-red-400" : "text-green-400" },
                  { n: num(s?.aiEvaluations), t: "AI evals", cls: "text-primary" },
                ].map((f) => (
                  <div key={f.t} className="rounded-lg border border-border bg-muted/30 p-2.5">
                    <div className={`font-mono text-xl font-bold tabular-nums ${f.cls}`}>{f.n}</div>
                    <div className="mt-0.5 font-mono text-[9px] uppercase tracking-[0.12em] text-muted-foreground">{f.t}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </Panel>

        <Panel>
          <SectionLabel>Controls Coverage</SectionLabel>
          <div className="mt-4">
            {cov && cov.controls.length ? <CoverageDonut controls={cov.controls} /> : <p className="text-sm text-muted-foreground">No controls defined yet.</p>}
          </div>
        </Panel>

        <Panel>
          <SectionLabel>Environments</SectionLabel>
          <div className="mt-4 flex items-center gap-4">
            <Ring value={envs.length ? secureEnvs / envs.length : 0} size={64} stroke={7} color="#35C08A">
              <span className="font-mono text-xs font-bold text-green-400">{secureEnvs}/{envs.length || 0}</span>
            </Ring>
            <div className="font-mono text-[11px] leading-relaxed text-muted-foreground">
              <span className="text-green-400">{envs.length && secureEnvs === envs.length ? "All secure" : `${envs.length - secureEnvs} drifting`}</span><br />
              {envs.length} workloads · {envs.length - secureEnvs} drift
            </div>
          </div>
          <div className="mt-4 flex max-h-[220px] flex-col gap-1.5 overflow-auto">
            {envs.map((e) => {
              const secure = !e.drifts?.length && !e.shadowChanges?.length;
              return (
                <div key={e.id} className="flex items-center gap-2 rounded-md border border-border bg-muted/20 px-2.5 py-1.5">
                  <span className={`size-1.5 rounded-full ${secure ? "bg-green-400" : "bg-red-400"}`} />
                  <span className="truncate font-mono text-xs">{e.name}</span>
                  <span className="ml-auto flex shrink-0 gap-1.5">
                    <span className="rounded bg-muted px-1.5 py-0.5 font-mono text-[9px] uppercase text-muted-foreground">{/aws|ecs|lambda/i.test(e.type + e.name) ? "AWS" : "K8s"}</span>
                    <span className={`rounded px-1.5 py-0.5 font-mono text-[9px] uppercase ${secure ? "bg-green-500/15 text-green-400" : "bg-red-500/15 text-red-400"}`}>{secure ? "Secure" : "Drift"}</span>
                  </span>
                </div>
              );
            })}
            {!envs.length && <p className="text-sm text-muted-foreground">No environments.</p>}
          </div>
        </Panel>
      </div>

      {/* Row 2 — KPI tiles */}
      <div className="mt-4 grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatTile label="Checks performed" value={num(s?.checksTotal)} sub="Cumulative attestations" icon={CheckCircle2} href="/attestations" />
        <StatTile label="Checks · last 24h" value={num(s?.checksLast24h)} sub="Throughput" icon={Zap} color="text-primary" />
        <StatTile label="Compliant checks" value={num(s?.compliant)} sub="Sealed &amp; verified" icon={ShieldCheck} color="text-green-400" href="/attestations?compliant=true" />
        <StatTile label="Tracked artifacts" value={num(s?.artifacts)} sub="Build artifacts" icon={Package} href="/artifacts" />
      </div>

      {/* Row 3 — live checks + integrations */}
      <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Panel className="lg:col-span-2">
          <div className="flex items-center justify-between">
            <SectionLabel>Live Checks</SectionLabel>
            <span className="flex items-center gap-1.5 font-mono text-[11px] uppercase tracking-wide text-green-400"><span className="size-1.5 rounded-full bg-green-400" />streaming</span>
          </div>
          <div className="mt-3 flex max-h-[420px] flex-col overflow-auto">
            {s?.recent?.length ? s.recent.map((e, i) => (
              <div key={e.name + e.at} className={`grid grid-cols-[auto_1fr_auto] items-center gap-3 border-b border-dashed border-border py-2.5 last:border-0 ${i === 0 && flashTop ? "animate-pulse" : ""}`}>
                <span className={`size-2.5 rounded-full border-2 ${e.compliant ? "border-green-400" : "border-red-400"}`} />
                <div className="min-w-0">
                  <div className="truncate font-mono text-[12.5px]">{e.name}</div>
                  <div className="font-mono text-[10.5px] text-muted-foreground">{e.kind}</div>
                </div>
                <span className={`rounded border px-2 py-1 font-mono text-[10px] uppercase tracking-[0.14em] ${e.compliant ? "border-green-500/40 bg-green-500/10 text-green-400" : "border-red-500/40 bg-red-500/10 text-red-400"}`}>{e.compliant ? "pass" : "fail"}</span>
              </div>
            )) : <p className="py-4 font-mono text-xs text-muted-foreground">Connecting to the attestation stream…</p>}
          </div>
        </Panel>

        <Panel>
          <SectionLabel>Integrations</SectionLabel>
          <div className="mt-3 flex flex-col gap-2">
            {events.length ? events.slice(0, 10).map((e, i) => {
              const ok = e.status === "delivered" || e.status === "success";
              return (
                <div key={i} className="flex items-center gap-2.5 font-mono text-[11.5px]">
                  <Zap className="size-3.5 shrink-0 text-primary" />
                  <span className="truncate text-muted-foreground">{e.event_type}</span>
                  <span className={`ml-auto shrink-0 text-[9.5px] uppercase tracking-[0.13em] ${ok ? "text-green-400" : e.status === "failed" ? "text-red-400" : "text-amber-400"}`}>{e.status}</span>
                </div>
              );
            }) : <p className="text-sm text-muted-foreground">No integration events yet.</p>}
          </div>
        </Panel>
      </div>
    </div>
  );
}
