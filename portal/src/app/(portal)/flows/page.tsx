"use client";

import { useEffect, useState } from "react";
import { apiGet, apiPost } from "@/lib/api";

type Flow = { id: string; name: string; description?: string; created_at?: string; updated_at?: string; tags?: Record<string, string> | string[] | null };
type ChainVerdict = { valid: boolean; count: number; broken_at: number; reason?: string };

function tagList(tags: Flow["tags"]): string[] {
  if (!tags) return [];
  if (Array.isArray(tags)) return tags.map(String);
  return Object.entries(tags).map(([k, v]) => `${k}=${v}`);
}

const input = "w-full rounded-md border border-border bg-background px-3 py-2 text-sm font-mono text-foreground";
const panel = "rounded-xl border border-border bg-card p-5";

export default function Flows() {
  const [flows, setFlows] = useState<Flow[]>([]);
  const [trail, setTrail] = useState("");
  const [chain, setChain] = useState<ChainVerdict | null>(null);
  const [nName, setNName] = useState(""); const [nDesc, setNDesc] = useState("");
  const [ffilter, setFfilter] = useState("");
  const [err, setErr] = useState("");

  const loadFlows = () => apiGet<Flow[]>("/api/v1/flows").then(setFlows).catch((e) => setErr(String(e.message || e)));
  useEffect(() => { loadFlows(); }, []);

  const createFlow = async () => {
    setErr("");
    try { await apiPost("/api/v1/flows", { name: nName, description: nDesc }); setNName(""); setNDesc(""); loadFlows(); }
    catch (e) { setErr(String((e as Error).message || e)); }
  };

  const verifyChain = async () => {
    setErr(""); setChain(null);
    try {
      setChain(await apiGet<ChainVerdict>(`/api/v1/trails/${trail}/verify-chain`));
    } catch (e) { setErr(String((e as Error).message || e)); }
  };

  return (
    <div className="max-w-4xl">
      <h1 className="text-xl font-semibold">Flows &amp; Trails</h1>
      <p className="mt-1 text-sm text-muted-foreground">Delivery pipelines and their build trails.</p>

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
          {flows.length > 0 ? (
            <div className="flex flex-col gap-2">
              {flows.filter((f) => f.name.toLowerCase().includes(ffilter.toLowerCase())).map((f) => (
                <div key={f.id} className="rounded-md border border-border p-3">
                  <div className="flex items-start justify-between gap-4">
                    <div className="min-w-0">
                      <span className="font-semibold">{f.name}</span>
                      {f.description && <div className="mt-0.5 text-sm text-muted-foreground">{f.description}</div>}
                      {tagList(f.tags).length > 0 && (
                        <div className="mt-2 flex flex-wrap gap-1.5">
                          {tagList(f.tags).map((t) => <span key={t} className="rounded bg-muted px-2 py-0.5 text-xs text-muted-foreground">{t}</span>)}
                        </div>
                      )}
                    </div>
                    <div className="shrink-0 text-right text-xs text-muted-foreground">
                      <div>last change</div>
                      <div>{((f.updated_at || f.created_at) || "").replace("T", " ").slice(0, 19)}</div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          ) : <p className="text-sm text-muted-foreground">No flows.</p>}
        </div>

        <div className={panel}>
          <h2 className="mb-3 text-xs font-semibold uppercase tracking-wide text-muted-foreground">Trail actions</h2>
          <label className="text-sm"><span className="text-muted-foreground">Trail ID</span>
            <input className={input} value={trail} onChange={(e) => setTrail(e.target.value)} placeholder="trail UUID" />
          </label>
          <div className="mt-3 flex flex-wrap items-center gap-3">
            <button onClick={verifyChain} disabled={!trail} className="rounded-md bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground disabled:opacity-50">Verify tamper-evidence chain</button>
            <a
              href={trail ? `/api/v1/trails/${trail}/audit-package` : undefined}
              className={`rounded-md border border-border px-4 py-2 text-sm ${trail ? "" : "pointer-events-none opacity-50"}`}
            >
              Download audit package
            </a>
          </div>
          {chain && (
            <div className={`mt-4 text-sm font-semibold ${chain.valid ? "text-green-400" : "text-red-400"}`}>
              {chain.valid ? `✅ Chain valid (${chain.count} attestations)` : `❌ Chain broken at #${chain.broken_at} — ${chain.reason || ""}`}
            </div>
          )}
        </div>

        {err && <p className="text-sm text-red-400">{err}</p>}
      </div>
    </div>
  );
}
