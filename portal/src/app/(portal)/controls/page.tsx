"use client";

import { useEffect, useState } from "react";
import { Info, Archive, ArchiveRestore } from "lucide-react";
import { apiGet, apiPost } from "@/lib/api";

type Control = { id: string; key: string; name: string; framework?: string; required_types?: string[]; archived?: boolean };
type Coverage = { total_environments: number; controls: { control: string; name: string; enforced_in: string[]; coverage: number }[] };

const input = "w-full rounded-md border border-border bg-background px-3 py-2 text-sm font-mono text-foreground";
const panel = "rounded-xl border border-border bg-card p-5";

// Ready-made starting points so the screen is usable immediately.
const TEMPLATES = [
  { key: "SOC2-CC7.1", name: "Vulnerability scanning", framework: "SOC2", required: "trivy,snyk" },
  { key: "SOC2-CC8.1", name: "Change is tested", framework: "SOC2", required: "junit" },
  { key: "ISO-A.12.6", name: "No critical CVEs", framework: "ISO27001", required: "snyk" },
  { key: "SLSA-BUILD", name: "SBOM produced", framework: "SLSA", required: "sbom-cyclonedx" },
];

export default function Controls() {
  const [controls, setControls] = useState<Control[]>([]);
  const [cov, setCov] = useState<Coverage | null>(null);
  const [showArchived, setShowArchived] = useState(false);
  const [key, setKey] = useState(""); const [name, setName] = useState("");
  const [framework, setFramework] = useState("SOC2"); const [require, setRequire] = useState("");
  const [msg, setMsg] = useState<{ t: string; ok: boolean }>({ t: "", ok: true });

  const load = () => {
    apiGet<Control[]>(`/api/v1/controls${showArchived ? "?include_archived=true" : ""}`).then(setControls).catch((e) => setMsg({ t: String(e.message), ok: false }));
    apiGet<Coverage>("/api/v1/controls/coverage").then(setCov).catch(() => {});
  };
  useEffect(() => { load(); }, [showArchived]); // eslint-disable-line react-hooks/exhaustive-deps

  const add = async () => {
    setMsg({ t: "", ok: true });
    try {
      await apiPost("/api/v1/controls", { key, name, framework, required_types: require.split(",").map((s) => s.trim()).filter(Boolean) });
      setKey(""); setName(""); setRequire(""); load();
    } catch (e) { setMsg({ t: String((e as Error).message), ok: false }); }
  };
  const applyTemplate = (t: typeof TEMPLATES[number]) => { setKey(t.key); setName(t.name); setFramework(t.framework); setRequire(t.required); };
  const setArchived = async (id: string, archived: boolean) => {
    try { await apiPost(`/api/v1/controls/${id}/${archived ? "archive" : "unarchive"}`, {}); load(); }
    catch (e) { setMsg({ t: String((e as Error).message), ok: false }); }
  };

  return (
    <div className="max-w-4xl">
      <h1 className="text-xl font-semibold">Controls &amp; Coverage</h1>
      <p className="mt-1 text-sm text-muted-foreground">Governance controls and how well your environments enforce them.</p>

      <div className="mt-4 flex items-start gap-2 rounded-md bg-muted/50 p-3 text-xs text-muted-foreground">
        <Info className="mt-0.5 size-4 shrink-0 text-primary" />
        <span>A <strong>control</strong> is a named governance requirement (e.g. <code className="rounded bg-muted px-1">SOC2-CC7.1</code> — &ldquo;artifacts must pass a vulnerability scan&rdquo;) mapped to the evidence types that satisfy it. <strong>Coverage</strong> shows, for each control, how many of your environments actually enforce it via a policy. Add one from a template below, or define your own.</span>
      </div>

      <div className="mt-6 flex flex-col gap-5">
        <div className={panel}>
          <h2 className="mb-3 text-xs font-semibold uppercase tracking-wide text-muted-foreground">Add control</h2>
          <div className="mb-3 flex flex-wrap gap-2">
            {TEMPLATES.map((t) => (
              <button key={t.key} onClick={() => applyTemplate(t)} className="rounded-full border border-border px-3 py-1 text-xs text-muted-foreground hover:border-primary/40 hover:text-foreground">{t.key} · {t.name}</button>
            ))}
          </div>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <input className={input} value={key} onChange={(e) => setKey(e.target.value)} placeholder="key (SOC2-CC7.1)" />
            <input className={input} value={name} onChange={(e) => setName(e.target.value)} placeholder="name" />
            <select className={input} value={framework} onChange={(e) => setFramework(e.target.value)}><option>SOC2</option><option>ISO27001</option><option>FDA-21CFR11</option><option>PCI-DSS</option><option>SLSA</option><option>Custom</option></select>
            <input className={input} value={require} onChange={(e) => setRequire(e.target.value)} placeholder="required evidence types (trivy,snyk)" />
          </div>
          <div className="mt-3 flex items-center gap-3">
            <button onClick={add} disabled={!key || !name} className="rounded-md bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground disabled:opacity-50">Add / Update</button>
            {msg.t && <span className={`text-sm ${msg.ok ? "text-green-400" : "text-red-400"}`}>{msg.t}</span>}
          </div>
        </div>

        <div className={panel}>
          <h2 className="mb-3 text-xs font-semibold uppercase tracking-wide text-muted-foreground">Coverage {cov ? `(${cov.total_environments} environments)` : ""}</h2>
          {cov && cov.controls.length ? (
            <div className="flex flex-col gap-3">
              {cov.controls.map((c) => (
                <div key={c.control}>
                  <div className="flex items-center justify-between text-sm">
                    <span className="font-mono">{c.control} <span className="text-muted-foreground">{c.name}</span></span>
                    <span className={c.coverage === 0 ? "text-red-400" : c.coverage < 1 ? "text-amber-400" : "text-green-400"}>{Math.round(c.coverage * 100)}%</span>
                  </div>
                  <div className="mt-1 h-2 w-full rounded-full bg-muted">
                    <div className={`h-2 rounded-full ${c.coverage === 0 ? "bg-red-500" : c.coverage < 1 ? "bg-amber-500" : "bg-green-500"}`} style={{ width: `${Math.round(c.coverage * 100)}%` }} />
                  </div>
                  <div className="mt-1 text-xs text-muted-foreground">{c.enforced_in.length ? `enforced in: ${c.enforced_in.join(", ")}` : "not enforced in any environment"}</div>
                </div>
              ))}
            </div>
          ) : <p className="text-sm text-muted-foreground">No active controls yet — add one above.</p>}
        </div>

        <div className={panel}>
          <div className="mb-3 flex items-center justify-between">
            <h2 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">All controls</h2>
            <label className="flex items-center gap-2 text-xs text-muted-foreground"><input type="checkbox" checked={showArchived} onChange={(e) => setShowArchived(e.target.checked)} /> show archived</label>
          </div>
          {controls.length ? (
            <div className="flex flex-col gap-2">
              {controls.map((c) => (
                <div key={c.id} className={`flex items-center justify-between rounded-md border border-border p-3 text-sm ${c.archived ? "opacity-50" : ""}`}>
                  <div>
                    <span className="font-mono font-medium">{c.key}</span> <span className="text-muted-foreground">{c.name}</span>
                    <div className="mt-0.5 flex flex-wrap gap-1.5">
                      {c.framework && <span className="rounded bg-muted px-2 py-0.5 text-xs text-muted-foreground">{c.framework}</span>}
                      {(c.required_types || []).map((t) => <span key={t} className="rounded bg-primary/10 px-2 py-0.5 text-xs text-primary">{t}</span>)}
                      {c.archived && <span className="rounded bg-muted px-2 py-0.5 text-xs text-muted-foreground">archived</span>}
                    </div>
                  </div>
                  {c.archived ? (
                    <button onClick={() => setArchived(c.id, false)} className="flex items-center gap-1.5 rounded-md border border-border px-3 py-1.5 text-xs"><ArchiveRestore className="size-3.5" /> Restore</button>
                  ) : (
                    <button onClick={() => setArchived(c.id, true)} className="flex items-center gap-1.5 rounded-md border border-border px-3 py-1.5 text-xs text-muted-foreground hover:text-foreground"><Archive className="size-3.5" /> Archive</button>
                  )}
                </div>
              ))}
            </div>
          ) : <p className="text-sm text-muted-foreground">No controls yet.</p>}
        </div>
      </div>
    </div>
  );
}
