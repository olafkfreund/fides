"use client";

import { useEffect, useState } from "react";
import { ChevronRight, ChevronDown, ShieldCheck, ShieldAlert } from "lucide-react";
import { apiGet, apiPost } from "@/lib/api";

type Flow = { id: string; name: string; description?: string; created_at?: string; updated_at?: string; tags?: Record<string, string> | string[] | null };
type Trail = { id: string; name: string; git_commit?: string; git_branch?: string; created_at?: string; attestations: number; compliant: boolean };
type FlowArtifact = { sha256: string; name: string; type?: string; git_commit?: string; created_at?: string; compliant: boolean };
type ChainVerdict = { valid: boolean; count: number; broken_at: number; reason?: string };
type GateEntry = { control: string; name: string; reasons: string[] };
type Approvals = { count: number; human_approvers: number; four_eyes: boolean; approvers: string[] };
type Gate = { approved: boolean; recommendation: string; risk_score: number; risk_level: string; passed: string[]; failed: GateEntry[]; missing_evidence: GateEntry[]; approvals?: Approvals; summary: string };

function tagList(tags: Flow["tags"]): string[] {
  if (!tags) return [];
  if (Array.isArray(tags)) return tags.map(String);
  return Object.entries(tags).map(([k, v]) => `${k}=${v}`);
}

const input = "w-full rounded-md border border-border bg-background px-3 py-2 text-sm font-mono text-foreground";
const panel = "rounded-xl border border-border bg-card p-5";

export default function Flows() {
  const [flows, setFlows] = useState<Flow[]>([]);
  const [ffilter, setFfilter] = useState("");
  const [nName, setNName] = useState(""); const [nDesc, setNDesc] = useState("");
  const [expanded, setExpanded] = useState<string | null>(null);
  const [trailsByFlow, setTrailsByFlow] = useState<Record<string, Trail[]>>({});
  const [artifactsByFlow, setArtifactsByFlow] = useState<Record<string, FlowArtifact[]>>({});
  const [subtab, setSubtab] = useState<Record<string, "trails" | "artifacts">>({});
  const [chain, setChain] = useState<Record<string, ChainVerdict>>({});
  const [gate, setGate] = useState<Record<string, Gate>>({});
  const [err, setErr] = useState("");

  const loadFlows = () => apiGet<Flow[]>("/api/v1/flows").then(setFlows).catch((e) => setErr(String(e.message || e)));
  useEffect(() => { loadFlows(); }, []);

  const createFlow = async () => {
    setErr("");
    try { await apiPost("/api/v1/flows", { name: nName, description: nDesc }); setNName(""); setNDesc(""); loadFlows(); }
    catch (e) { setErr(String((e as Error).message || e)); }
  };

  const toggle = async (id: string) => {
    if (expanded === id) { setExpanded(null); return; }
    setExpanded(id);
    if (!trailsByFlow[id]) {
      try {
        const trails = await apiGet<Trail[]>(`/api/v1/flows/${id}/trails`);
        setTrailsByFlow((m) => ({ ...m, [id]: trails || [] }));
      } catch (e) { setErr(String((e as Error).message || e)); }
    }
  };

  const loadArtifacts = async (id: string) => {
    if (artifactsByFlow[id]) return;
    try { const a = await apiGet<FlowArtifact[]>(`/api/v1/flows/${id}/artifacts`); setArtifactsByFlow((m) => ({ ...m, [id]: a || [] })); }
    catch (e) { setErr(String((e as Error).message || e)); }
  };

  const verifyTrail = async (trailId: string) => {
    try {
      const v = await apiGet<ChainVerdict>(`/api/v1/trails/${trailId}/verify-chain`);
      setChain((c) => ({ ...c, [trailId]: v }));
    } catch (e) { setErr(String((e as Error).message || e)); }
  };

  const evalGate = async (trailId: string) => {
    try {
      const g = await apiGet<Gate>(`/api/v1/trails/${trailId}/change-gate`);
      setGate((c) => ({ ...c, [trailId]: g }));
    } catch (e) { setErr(String((e as Error).message || e)); }
  };

  const approveTrail = async (trailId: string) => {
    try {
      await apiPost(`/api/v1/trails/${trailId}/approvals`, { reason: "Approved in the Fides portal" });
      evalGate(trailId);
    } catch (e) { setErr(String((e as Error).message || e)); }
  };

  const shown = flows.filter((f) => f.name.toLowerCase().includes(ffilter.toLowerCase()));

  return (
    <div className="max-w-4xl">
      <h1 className="text-xl font-semibold">Flows &amp; Trails</h1>
      <p className="mt-1 text-sm text-muted-foreground">Delivery pipelines and their build trails. Click a flow to see its trails.</p>

      <div className="mt-6 flex flex-col gap-5">
        <div className={panel}>
          <h2 className="mb-3 text-xs font-semibold uppercase tracking-wide text-muted-foreground">New Flow</h2>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
            <input className={input} value={nName} onChange={(e) => setNName(e.target.value)} placeholder="flow name" />
            <input className={input} value={nDesc} onChange={(e) => setNDesc(e.target.value)} placeholder="description" />
            <button onClick={createFlow} disabled={!nName} className="rounded-md bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground disabled:opacity-50">Create flow</button>
          </div>
        </div>

        <div className={panel}>
          <div className="mb-3 flex items-center justify-between">
            <h2 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">Flows</h2>
            <input className="w-56 rounded-md border border-border bg-background px-3 py-1.5 text-sm" value={ffilter} onChange={(e) => setFfilter(e.target.value)} placeholder="Filter by name…" />
          </div>
          {shown.length === 0 && <p className="text-sm text-muted-foreground">No flows.</p>}
          <div className="flex flex-col gap-2">
            {shown.map((f) => {
              const open = expanded === f.id;
              const trails = trailsByFlow[f.id];
              const arts = artifactsByFlow[f.id];
              const tab = subtab[f.id] || "trails";
              return (
                <div key={f.id} className="rounded-md border border-border">
                  <button onClick={() => toggle(f.id)} className="flex w-full items-start justify-between gap-4 p-3 text-left hover:bg-accent/50">
                    <div className="min-w-0">
                      <span className="flex items-center gap-1.5 font-semibold">
                        {open ? <ChevronDown className="size-4 text-muted-foreground" /> : <ChevronRight className="size-4 text-muted-foreground" />}
                        {f.name}
                      </span>
                      {f.description && <div className="mt-0.5 pl-5 text-sm text-muted-foreground">{f.description}</div>}
                      {tagList(f.tags).length > 0 && (
                        <div className="mt-2 flex flex-wrap gap-1.5 pl-5">
                          {tagList(f.tags).map((t) => <span key={t} className="rounded bg-muted px-2 py-0.5 text-xs text-muted-foreground">{t}</span>)}
                        </div>
                      )}
                    </div>
                    <div className="shrink-0 text-right text-xs text-muted-foreground">last change<br />{((f.updated_at || f.created_at) || "").replace("T", " ").slice(0, 19)}</div>
                  </button>

                  {open && (
                    <div className="border-t border-border p-3">
                      <div className="mb-3 flex gap-1">
                        <button onClick={() => setSubtab((s) => ({ ...s, [f.id]: "trails" }))} className={`rounded-md px-3 py-1 text-xs ${tab === "trails" ? "bg-primary/15 text-foreground" : "text-muted-foreground"}`}>Trails</button>
                        <button onClick={() => { setSubtab((s) => ({ ...s, [f.id]: "artifacts" })); loadArtifacts(f.id); }} className={`rounded-md px-3 py-1 text-xs ${tab === "artifacts" ? "bg-primary/15 text-foreground" : "text-muted-foreground"}`}>Artifacts</button>
                      </div>
                      {tab === "artifacts" ? (
                        !arts ? <p className="text-sm text-muted-foreground">Loading artifacts…</p> : arts.length === 0 ? <p className="text-sm text-muted-foreground">No artifacts recorded for this flow.</p> : (
                          <div className="flex flex-col gap-2">
                            {arts.map((a) => (
                              <div key={a.sha256} className="rounded-md border border-border p-3">
                                <div className="flex items-center justify-between gap-3">
                                  <span className="flex items-center gap-1.5 text-sm font-medium">{a.compliant ? <ShieldCheck className="size-4 text-green-400" /> : <ShieldAlert className="size-4 text-red-400" />}{a.name} <span className="text-xs font-normal text-muted-foreground">· {a.type}</span></span>
                                  <span className="font-mono text-xs text-muted-foreground">{a.git_commit ? a.git_commit.slice(0, 10) : ""}</span>
                                </div>
                                <div className="mt-1 break-all font-mono text-xs text-muted-foreground">{a.sha256}</div>
                              </div>
                            ))}
                          </div>
                        )
                      ) : !trails ? <p className="text-sm text-muted-foreground">Loading trails…</p> : trails.length === 0 ? (
                        <p className="text-sm text-muted-foreground">No trails recorded for this flow yet.</p>
                      ) : (
                        <div className="flex flex-col gap-2">
                          {trails.map((t) => {
                            const v = chain[t.id];
                            return (
                              <div key={t.id} className="rounded-md border border-border p-3">
                                <div className="flex flex-wrap items-center justify-between gap-3">
                                  <div className="min-w-0">
                                    <span className="flex items-center gap-1.5 text-sm font-medium">
                                      {t.compliant ? <ShieldCheck className="size-4 text-green-400" /> : <ShieldAlert className="size-4 text-red-400" />}
                                      {t.name}
                                    </span>
                                    <div className="mt-0.5 font-mono text-xs text-muted-foreground">
                                      {t.git_commit ? `${t.git_commit.slice(0, 10)} ` : ""}{t.git_branch ? `· ${t.git_branch} ` : ""}· {t.attestations} attestations · {(t.created_at || "").replace("T", " ").slice(0, 19)}
                                    </div>
                                  </div>
                                  <div className="flex shrink-0 gap-2">
                                    <button onClick={() => evalGate(t.id)} className="rounded-md bg-primary px-3 py-1.5 text-xs font-semibold text-primary-foreground">Change Gate</button>
                                    <button onClick={() => approveTrail(t.id)} className="rounded-md border border-border px-3 py-1.5 text-xs">Approve</button>
                                    <button onClick={() => verifyTrail(t.id)} className="rounded-md border border-border px-3 py-1.5 text-xs">Verify chain</button>
                                    <a href={`/api/v1/trails/${t.id}/audit-package`} className="rounded-md border border-border px-3 py-1.5 text-xs">Download audit</a>
                                  </div>
                                </div>
                                {v && (
                                  <div className={`mt-2 text-xs font-medium ${v.valid ? "text-green-400" : "text-red-400"}`}>
                                    {v.valid ? `✅ Tamper-evidence chain valid (${v.count} attestations)` : `❌ Chain broken at #${v.broken_at} — ${v.reason || ""}`}
                                  </div>
                                )}
                                {gate[t.id] && (
                                  <div className="mt-2 rounded-md border border-border bg-background p-2 text-xs">
                                    <div className="flex flex-wrap items-center gap-2">
                                      <span className={`rounded px-2 py-0.5 font-medium ${gate[t.id].approved ? "bg-green-500/15 text-green-400" : "bg-red-500/15 text-red-400"}`}>{gate[t.id].approved ? "RECOMMEND APPROVE" : "HOLD"}</span>
                                      <span className={`rounded px-2 py-0.5 font-medium ${gate[t.id].risk_level === "high" ? "text-red-400" : gate[t.id].risk_level === "medium" ? "text-amber-400" : "text-green-400"}`}>risk {gate[t.id].risk_score} · {gate[t.id].risk_level}</span>
                                      {gate[t.id].approvals && (
                                        <span className={`rounded px-2 py-0.5 font-medium ${gate[t.id].approvals!.human_approvers > 0 ? "text-green-400" : "text-amber-400"}`}>
                                          {gate[t.id].approvals!.human_approvers} approval{gate[t.id].approvals!.human_approvers === 1 ? "" : "s"}{gate[t.id].approvals!.four_eyes ? " · four-eyes ✓" : ""}
                                        </span>
                                      )}
                                    </div>
                                    <div className="mt-1 text-muted-foreground">{gate[t.id].summary}</div>
                                    {gate[t.id].failed.length > 0 && <div className="mt-1 text-red-400">failed: {gate[t.id].failed.map((f) => f.control).join(", ")}</div>}
                                    {gate[t.id].missing_evidence.length > 0 && <div className="mt-1 text-amber-400">missing: {gate[t.id].missing_evidence.map((f) => f.control).join(", ")}</div>}
                                    {gate[t.id].passed.length > 0 && <div className="mt-1 text-green-400">passed: {gate[t.id].passed.join(", ")}</div>}
                                  </div>
                                )}
                              </div>
                            );
                          })}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>

        {err && <p className="text-sm text-red-400">{err}</p>}
      </div>
    </div>
  );
}
