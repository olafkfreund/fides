"use client";

import { useEffect, useState } from "react";
import { apiGet } from "@/lib/api";

type Flow = { id: string; name: string; description?: string; created_at?: string };
type ChainVerdict = { valid: boolean; count: number; broken_at: number; reason?: string };

const input = "w-full rounded-md border border-border bg-background px-3 py-2 text-sm font-mono text-foreground";
const panel = "rounded-xl border border-border bg-card p-5";

export default function Flows() {
  const [flows, setFlows] = useState<Flow[]>([]);
  const [trail, setTrail] = useState("");
  const [chain, setChain] = useState<ChainVerdict | null>(null);
  const [err, setErr] = useState("");

  useEffect(() => {
    apiGet<Flow[]>("/api/v1/flows").then(setFlows).catch((e) => setErr(String(e.message || e)));
  }, []);

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
          <h2 className="mb-3 text-xs font-semibold uppercase tracking-wide text-muted-foreground">Flows</h2>
          {flows.length > 0 ? (
            <table className="w-full text-left text-sm">
              <thead className="text-muted-foreground"><tr><th className="py-1">Name</th><th>Description</th><th>Created</th></tr></thead>
              <tbody>{flows.map((f) => (
                <tr key={f.id} className="border-t border-border">
                  <td className="py-2 font-mono">{f.name}</td>
                  <td className="text-muted-foreground">{f.description}</td>
                  <td className="text-muted-foreground">{(f.created_at || "").replace("T", " ").slice(0, 19)}</td>
                </tr>
              ))}</tbody>
            </table>
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
