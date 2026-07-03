"use client";

import { useEffect, useState } from "react";
import { CheckCircle2, XCircle, ChevronRight } from "lucide-react";
import { apiGet } from "@/lib/api";

type Att = { id: string; name: string; type_name: string; is_compliant: boolean; trail_id: string; created_at?: string };
type AttDetail = Att & { payload?: unknown; signed_by?: string; signature_algorithm?: string; content_hash?: string; artifact_sha256?: string };

const control = "rounded-md border border-border bg-background px-3 py-2 text-sm";

export default function Attestations() {
  const [atts, setAtts] = useState<Att[]>([]);
  const [type, setType] = useState("");
  const [compliance, setCompliance] = useState("");
  const [name, setName] = useState("");
  const [loading, setLoading] = useState(false);
  const [open, setOpen] = useState<Record<string, AttDetail>>({});
  const [err, setErr] = useState("");

  const toggle = async (id: string) => {
    if (open[id]) { setOpen((s) => { const n = { ...s }; delete n[id]; return n; }); return; }
    try { const d = await apiGet<AttDetail>(`/api/v1/attestations/${id}`); setOpen((s) => ({ ...s, [id]: d })); }
    catch (e) { setErr(String((e as Error).message)); }
  };

  const load = (over?: { type?: string; compliance?: string }) => {
    const t = over?.type ?? type;
    const c = over?.compliance ?? compliance;
    const q = new URLSearchParams();
    if (t) q.set("type", t);
    if (c) q.set("compliant", c);
    setLoading(true);
    apiGet<Att[]>(`/api/v1/search/attestations?${q}`)
      .then((a) => setAtts(a || []))
      .catch((e) => setErr(String(e.message || e)))
      .finally(() => setLoading(false));
  };
  // Preset filters from the URL so dashboard deep-links (e.g. ?compliant=false for
  // "Active Alerts") land pre-filtered. Static export → read window.location directly.
  useEffect(() => {
    const sp = new URLSearchParams(window.location.search);
    const c = sp.get("compliant") || "";
    const t = sp.get("type") || "";
    // eslint-disable-next-line react-hooks/set-state-in-effect
    if (c) setCompliance(c);
    if (t) setType(t);
    const timer = setTimeout(() => load({ compliance: c, type: t }), 0);
    return () => clearTimeout(timer);
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const shown = atts.filter((a) => a.name.toLowerCase().includes(name.toLowerCase()));
  const compliant = atts.filter((a) => a.is_compliant).length;
  const types = [...new Set(atts.map((a) => a.type_name))];

  return (
    <div>
      <h1 className="text-xl font-semibold">Attestations</h1>
      <p className="mt-1 text-sm text-muted-foreground">Evidence recorded against build trails.</p>

      <div className="mt-6 grid grid-cols-1 gap-4 sm:grid-cols-3">
        <div className="rounded-xl border border-border bg-card p-5"><div className="text-xs uppercase tracking-wide text-muted-foreground">Total</div><div className="mt-2 text-2xl font-semibold">{atts.length}</div></div>
        <div className="rounded-xl border border-border bg-card p-5"><div className="text-xs uppercase tracking-wide text-muted-foreground">Compliant</div><div className="mt-2 text-2xl font-semibold text-green-400">{atts.length ? Math.round((compliant / atts.length) * 100) : 0}%</div><div className="mt-1 text-xs text-muted-foreground">{compliant} of {atts.length}</div></div>
        <div className="rounded-xl border border-border bg-card p-5"><div className="text-xs uppercase tracking-wide text-muted-foreground">Evidence Types</div><div className="mt-2 text-2xl font-semibold">{types.length}</div></div>
      </div>

      <div className="mt-6 rounded-xl border border-border bg-card p-5">
        <div className="mb-4 flex flex-wrap items-center gap-3">
          <input className={`${control} w-56`} value={name} onChange={(e) => setName(e.target.value)} placeholder="Find by name…" />
          <input className={`${control} w-48`} value={type} onChange={(e) => setType(e.target.value)} placeholder="Type (junit, snyk…)" />
          <select className={control} value={compliance} onChange={(e) => setCompliance(e.target.value)}>
            <option value="">Any compliance</option><option value="true">Compliant</option><option value="false">Non-compliant</option>
          </select>
          <button onClick={load} className="rounded-md bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground">Apply</button>
        </div>

        {loading ? <p className="text-sm text-muted-foreground">Loading…</p> : shown.length ? (
          <div className="flex flex-col divide-y divide-border">
            {shown.map((a) => {
              const d = open[a.id];
              return (
                <div key={a.id} className="py-2.5">
                  <button onClick={() => toggle(a.id)} aria-expanded={!!d} className="flex w-full items-center gap-3 text-left">
                    <ChevronRight className={`size-4 shrink-0 text-muted-foreground transition-transform ${d ? "rotate-90" : ""}`} />
                    {a.is_compliant ? <CheckCircle2 className="size-4 shrink-0 text-green-400" /> : <XCircle className="size-4 shrink-0 text-red-400" />}
                    <div className="min-w-0 flex-1">
                      <div className="truncate text-sm font-medium">{a.name}</div>
                      <div className="truncate font-mono text-xs text-muted-foreground">trail {a.trail_id.slice(0, 8)} · {(a.created_at || "").replace("T", " ").slice(0, 19)}</div>
                    </div>
                    <span className="rounded bg-muted px-2 py-0.5 text-xs text-muted-foreground">{a.type_name}</span>
                    <span className={`w-24 text-right text-xs font-medium ${a.is_compliant ? "text-green-400" : "text-red-400"}`}>{a.is_compliant ? "Compliant" : "Non-compliant"}</span>
                  </button>
                  {d && (
                    <div className="mt-2 space-y-2 pl-11">
                      {(d.signed_by || d.content_hash || d.artifact_sha256) && (
                        <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground">
                          {d.artifact_sha256 && <span>artifact <code className="font-mono">{d.artifact_sha256.slice(0, 16)}…</code></span>}
                          {d.signed_by && <span>signed by <span className="text-foreground">{d.signed_by}</span>{d.signature_algorithm ? ` (${d.signature_algorithm})` : ""}</span>}
                          {d.content_hash && <span>chain hash <code className="font-mono">{d.content_hash.slice(0, 16)}…</code></span>}
                        </div>
                      )}
                      <pre className="max-h-72 overflow-auto rounded-md border border-border bg-background p-3 font-mono text-xs leading-relaxed text-foreground/90">{d.payload != null ? JSON.stringify(d.payload, null, 2) : "(no payload)"}</pre>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        ) : <p className="text-sm text-muted-foreground">No attestations match.</p>}
      </div>

      {err && <p className="mt-4 text-sm text-red-400">{err}</p>}
    </div>
  );
}
