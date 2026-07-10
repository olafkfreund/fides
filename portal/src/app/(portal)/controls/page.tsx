"use client";

import { useEffect, useState } from "react";
import { Info, Archive, ArchiveRestore, ShieldCheck, ChevronRight, Check, Plus, Loader2 } from "lucide-react";
import { apiGet, apiPost } from "@/lib/api";

type Control = { id: string; key: string; name: string; framework?: string; required_types?: string[]; archived?: boolean };
type CovControl = { control: string; name: string; framework?: string; enforced_in: string[]; coverage: number };
type Coverage = { total_environments: number; controls: CovControl[] };
type Env = { id: string; name: string };

const input = "w-full rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground";
const mono = "w-full rounded-md border border-border bg-background px-3 py-2 text-sm font-mono text-foreground";
const panel = "rounded-xl border border-border bg-card p-5";

// Ready-made starting points so the screen is usable immediately.
const TEMPLATES = [
  { key: "SOC2-CC7.1", name: "Vulnerability scanning", framework: "SOC2", required: "trivy,snyk" },
  { key: "SOC2-CC8.1", name: "Change is tested", framework: "SOC2", required: "junit" },
  { key: "ISO-A.12.6", name: "No critical CVEs", framework: "ISO27001", required: "snyk" },
  { key: "SLSA-BUILD", name: "SBOM produced", framework: "SLSA", required: "sbom-cyclonedx" },
];

function pctColor(c: number) {
  return c === 0 ? "text-red-400" : c < 1 ? "text-amber-400" : "text-green-400";
}
function barColor(c: number) {
  return c === 0 ? "bg-red-500" : c < 1 ? "bg-amber-500" : "bg-green-500";
}

export default function Controls() {
  const [controls, setControls] = useState<Control[]>([]);
  const [cov, setCov] = useState<Coverage | null>(null);
  const [envs, setEnvs] = useState<Env[]>([]);
  const [open, setOpen] = useState<Set<string>>(new Set()); // expanded control keys
  const [enforcing, setEnforcing] = useState(""); // "<key>|<envId|all>" in flight
  const [showArchived, setShowArchived] = useState(false);
  const [showAdd, setShowAdd] = useState(false);
  const [key, setKey] = useState(""); const [name, setName] = useState("");
  const [framework, setFramework] = useState("SOC2"); const [require, setRequire] = useState("");
  const [adopt, setAdopt] = useState("SOC2");
  const [msg, setMsg] = useState<{ t: string; ok: boolean }>({ t: "", ok: true });

  const load = () => {
    apiGet<Control[]>(`/api/v1/controls?include_archived=true`).then(setControls).catch((e) => setMsg({ t: String(e.message), ok: false }));
    apiGet<Coverage>("/api/v1/controls/coverage").then(setCov).catch(() => {});
    apiGet<Env[]>("/api/v1/environments").then((e) => setEnvs(e || [])).catch(() => {});
  };
  useEffect(() => { load(); }, []);

  const toggle = (k: string) => setOpen((s) => { const n = new Set(s); if (n.has(k)) n.delete(k); else n.add(k); return n; });

  const importFramework = async () => {
    setMsg({ t: "", ok: true });
    try {
      const r = await apiPost<{ imported: number }>("/api/v1/controls/import-framework", { framework: adopt });
      setMsg({ t: `Imported ${r.imported} ${adopt} controls.`, ok: true });
      load();
    } catch (e) { setMsg({ t: String((e as Error).message), ok: false }); }
  };

  // Enforce a control: envId undefined => all environments.
  const enforce = async (control: string, envId?: string) => {
    const tag = `${control}|${envId || "all"}`;
    setEnforcing(tag); setMsg({ t: "", ok: true });
    try {
      const body = envId ? { environment_id: envId } : { all: true };
      const r = await apiPost<{ environments: number }>(`/api/v1/controls/${encodeURIComponent(control)}/enforce`, body);
      setMsg({ t: `Enforced ${control}${r.environments != null ? ` in ${r.environments} environment${r.environments === 1 ? "" : "s"}` : ""}.`, ok: true });
      load();
    } catch (e) { setMsg({ t: String((e as Error).message), ok: false }); }
    finally { setEnforcing(""); }
  };

  const add = async () => {
    setMsg({ t: "", ok: true });
    try {
      await apiPost("/api/v1/controls", { key, name, framework, required_types: require.split(",").map((s) => s.trim()).filter(Boolean) });
      setKey(""); setName(""); setRequire(""); setMsg({ t: `Control ${key} saved.`, ok: true }); load();
    } catch (e) { setMsg({ t: String((e as Error).message), ok: false }); }
  };
  const applyTemplate = (t: typeof TEMPLATES[number]) => { setKey(t.key); setName(t.name); setFramework(t.framework); setRequire(t.required); };
  const setArchived = async (id: string, archived: boolean) => {
    try { await apiPost(`/api/v1/controls/${id}/${archived ? "archive" : "unarchive"}`, {}); load(); }
    catch (e) { setMsg({ t: String((e as Error).message), ok: false }); }
  };

  // --- derived views ---
  const ctrlByKey: Record<string, Control> = Object.fromEntries(controls.map((c) => [c.key, c]));
  const covControls = cov?.controls ?? [];
  const totalEnvs = cov?.total_environments ?? 0;
  const fully = covControls.filter((c) => c.coverage >= 1).length;
  const gaps = covControls.length - fully;
  const avg = covControls.length ? Math.round((covControls.reduce((s, c) => s + c.coverage, 0) / covControls.length) * 100) : 0;
  // Group coverage by framework; within a group, least-covered first (actionable).
  const groups: Record<string, CovControl[]> = {};
  for (const c of covControls) (groups[c.framework || "Other"] ??= []).push(c);
  for (const k of Object.keys(groups)) groups[k].sort((a, b) => a.coverage - b.coverage);
  const groupNames = Object.keys(groups).sort();
  const archived = controls.filter((c) => c.archived);

  return (
    <div>
      <h1 className="text-xl font-semibold">Controls &amp; Coverage</h1>
      <p className="mt-1 text-sm text-muted-foreground">Governance controls and how well your environments enforce them.</p>

      {/* At-a-glance summary */}
      <div className="mt-6 grid grid-cols-2 gap-4 sm:grid-cols-4">
        {[
          { label: "Controls", value: String(covControls.length), sub: `${groupNames.length} frameworks` },
          { label: "Avg coverage", value: `${avg}%`, sub: `across ${totalEnvs} environments`, cls: pctColor(avg / 100) },
          { label: "Fully covered", value: String(fully), sub: "enforced everywhere", cls: fully ? "text-green-400" : "text-muted-foreground" },
          { label: "Gaps", value: String(gaps), sub: "need attention", cls: gaps ? "text-amber-400" : "text-green-400" },
        ].map((s) => (
          <div key={s.label} className={panel}>
            <div className="text-xs uppercase tracking-wide text-muted-foreground">{s.label}</div>
            <div className={`mt-1 text-2xl font-semibold ${s.cls || ""}`}>{s.value}</div>
            <div className="mt-0.5 text-xs text-muted-foreground">{s.sub}</div>
          </div>
        ))}
      </div>

      {msg.t && <p className={`mt-4 text-sm ${msg.ok ? "text-green-400" : "text-red-400"}`}>{msg.t}</p>}

      {/* Coverage — the primary view, grouped by framework, expandable per control */}
      <div className="mt-6 flex flex-col gap-4">
        {groupNames.length ? groupNames.map((fw) => {
          const items = groups[fw];
          const gCovered = items.filter((c) => c.coverage >= 1).length;
          return (
            <details key={fw} open className={panel}>
              <summary className="flex cursor-pointer list-none items-center justify-between">
                <span className="text-sm font-semibold">{fw}</span>
                <span className="text-xs text-muted-foreground">{gCovered}/{items.length} fully covered</span>
              </summary>
              <div className="mt-3 flex flex-col divide-y divide-border">
                {items.map((c) => {
                  const isOpen = open.has(c.control);
                  const ctrl = ctrlByKey[c.control];
                  const enforcedNames = new Set(c.enforced_in);
                  return (
                    <div key={c.control} className="py-2.5 first:pt-0">
                      <button onClick={() => toggle(c.control)} aria-expanded={isOpen} className="flex w-full items-center gap-3 text-left">
                        <ChevronRight className={`size-4 shrink-0 text-muted-foreground transition-transform ${isOpen ? "rotate-90" : ""}`} />
                        <span className="min-w-0 flex-1 truncate text-sm"><span className="font-mono">{c.control}</span> <span className="text-muted-foreground">{c.name}</span></span>
                        <span className="h-1.5 w-24 shrink-0 rounded-full bg-muted"><span className={`block h-1.5 rounded-full ${barColor(c.coverage)}`} style={{ width: `${Math.round(c.coverage * 100)}%` }} /></span>
                        <span className={`w-10 shrink-0 text-right text-sm ${pctColor(c.coverage)}`}>{Math.round(c.coverage * 100)}%</span>
                      </button>

                      {isOpen && (
                        <div className="mt-3 space-y-3 pl-7 text-sm">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className="text-xs text-muted-foreground">Requires evidence:</span>
                            {(ctrl?.required_types || []).length
                              ? (ctrl?.required_types || []).map((t) => <span key={t} className="rounded bg-primary/10 px-2 py-0.5 text-xs text-primary">{t}</span>)
                              : <span className="text-xs text-muted-foreground">no evidence types set</span>}
                          </div>
                          <div>
                            <div className="mb-1.5 flex items-center justify-between">
                              <span className="text-xs text-muted-foreground">Enforcement by environment ({c.enforced_in.length}/{totalEnvs})</span>
                              {c.coverage < 1 && (
                                <button onClick={() => enforce(c.control)} disabled={enforcing === `${c.control}|all`}
                                  className="flex items-center gap-1 rounded-md border border-primary/40 bg-primary/10 px-2.5 py-1 text-xs font-medium text-primary hover:bg-primary/20 disabled:opacity-50">
                                  {enforcing === `${c.control}|all` ? <Loader2 className="size-3.5 animate-spin" /> : <ShieldCheck className="size-3.5" />} Enforce everywhere
                                </button>
                              )}
                            </div>
                            <div className="grid grid-cols-1 gap-1.5 sm:grid-cols-2">
                              {envs.map((e) => {
                                const on = enforcedNames.has(e.name);
                                const busy = enforcing === `${c.control}|${e.id}`;
                                return (
                                  <div key={e.id} className="flex items-center justify-between rounded-md border border-border px-2.5 py-1.5">
                                    <span className="flex items-center gap-1.5 truncate">
                                      {on ? <Check className="size-3.5 shrink-0 text-green-400" /> : <span className="size-3.5 shrink-0 rounded-full border border-muted-foreground/40" />}
                                      <span className={`truncate ${on ? "" : "text-muted-foreground"}`}>{e.name}</span>
                                    </span>
                                    {on
                                      ? <span className="text-xs text-green-400">enforced</span>
                                      : <button onClick={() => enforce(c.control, e.id)} disabled={busy} className="rounded border border-primary/40 px-2 py-0.5 text-xs text-primary hover:bg-primary/10 disabled:opacity-50">{busy ? "…" : "Enforce"}</button>}
                                  </div>
                                );
                              })}
                              {!envs.length && <p className="text-xs text-muted-foreground">No environments defined.</p>}
                            </div>
                          </div>
                          {ctrl && (
                            <button onClick={() => setArchived(ctrl.id, true)} className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground"><Archive className="size-3.5" /> Archive this control</button>
                          )}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </details>
          );
        }) : <p className={`${panel} text-sm text-muted-foreground`}>No active controls yet — add one or import a framework below.</p>}
      </div>

      {/* Add / import controls — secondary, collapsed by default so coverage stays front-and-center */}
      <details className={`${panel} mt-6`} open={showAdd} onToggle={(e) => setShowAdd((e.target as HTMLDetailsElement).open)}>
        <summary className="flex cursor-pointer list-none items-center gap-2 text-sm font-semibold"><Plus className="size-4" /> Add or import controls</summary>

        <div className="mt-4 flex items-start gap-2 rounded-md bg-muted/50 p-3 text-xs text-muted-foreground">
          <Info className="mt-0.5 size-4 shrink-0 text-primary" />
          <span>A <strong>control</strong> is a governance requirement (e.g. <code className="rounded bg-muted px-1">SOC2-CC7.1</code>) mapped to the evidence types that satisfy it. Import a whole framework catalog, or define one control at a time.</span>
        </div>

        {/* Import a framework */}
        <div className="mt-4">
          <div className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">Import a framework catalog</div>
          <p className="mb-2 text-xs text-muted-foreground">Seeds a full set of controls mapped to evidence types in one click.</p>
          <div className="flex flex-wrap items-center gap-3">
            <select className={`${input} w-56`} value={adopt} onChange={(e) => setAdopt(e.target.value)}>
              <option value="SOC2">SOC 2</option><option value="ISO27001">ISO 27001</option><option value="NIST-800-53">NIST 800-53</option><option value="PCI-DSS">PCI-DSS</option><option value="DORA">DORA</option><option value="PSD2">PSD2</option><option value="SOX">SOX</option>
            </select>
            <button onClick={importFramework} className="rounded-md bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground">Import controls</button>
            <a href={`/api/v1/reports/framework/${encodeURIComponent(adopt)}`} target="_blank" className="rounded-md border border-border px-4 py-2 text-sm">Audit report</a>
          </div>
        </div>

        {/* Add a single control */}
        <div className="mt-6 border-t border-border pt-4">
          <div className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">Add a single control</div>
          <div className="mb-3 mt-2 flex flex-wrap gap-2">
            <span className="self-center text-xs text-muted-foreground">Start from a template:</span>
            {TEMPLATES.map((t) => (
              <button key={t.key} onClick={() => applyTemplate(t)} className="rounded-full border border-border px-3 py-1 text-xs text-muted-foreground hover:border-primary/40 hover:text-foreground">{t.key} · {t.name}</button>
            ))}
          </div>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <label className="block text-sm">
              <span className="text-muted-foreground">Control ID</span>
              <input className={mono} value={key} onChange={(e) => setKey(e.target.value)} placeholder="SOC2-CC7.1" />
              <span className="mt-1 block text-xs text-muted-foreground">A unique key for this control.</span>
            </label>
            <label className="block text-sm">
              <span className="text-muted-foreground">Name</span>
              <input className={input} value={name} onChange={(e) => setName(e.target.value)} placeholder="Artifacts pass a vulnerability scan" />
              <span className="mt-1 block text-xs text-muted-foreground">What the control requires, in plain words.</span>
            </label>
            <label className="block text-sm">
              <span className="text-muted-foreground">Framework</span>
              <select className={input} value={framework} onChange={(e) => setFramework(e.target.value)}><option>SOC2</option><option>ISO27001</option><option>FDA-21CFR11</option><option>PCI-DSS</option><option>SLSA</option><option>Custom</option></select>
              <span className="mt-1 block text-xs text-muted-foreground">The standard this control belongs to.</span>
            </label>
            <label className="block text-sm">
              <span className="text-muted-foreground">Required evidence types</span>
              <input className={mono} value={require} onChange={(e) => setRequire(e.target.value)} placeholder="trivy, snyk" />
              <span className="mt-1 block text-xs text-muted-foreground">Comma-separated attestation types that satisfy it (e.g. junit, trivy, snyk, sbom-cyclonedx).</span>
            </label>
          </div>
          <button onClick={add} disabled={!key || !name} className="mt-4 rounded-md bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground disabled:opacity-50">Add / update control</button>
        </div>
      </details>

      {/* Archived controls */}
      {(archived.length > 0 || showArchived) && (
        <details className={`${panel} mt-4`} onToggle={(e) => setShowArchived((e.target as HTMLDetailsElement).open)}>
          <summary className="cursor-pointer list-none text-xs font-semibold uppercase tracking-wide text-muted-foreground">Archived controls ({archived.length})</summary>
          <div className="mt-3 flex flex-col gap-2">
            {archived.length ? archived.map((c) => (
              <div key={c.id} className="flex items-center justify-between rounded-md border border-border p-3 text-sm opacity-70">
                <span><span className="font-mono font-medium">{c.key}</span> <span className="text-muted-foreground">{c.name}</span></span>
                <button onClick={() => setArchived(c.id, false)} className="flex items-center gap-1.5 rounded-md border border-border px-3 py-1.5 text-xs"><ArchiveRestore className="size-3.5" /> Restore</button>
              </div>
            )) : <p className="text-sm text-muted-foreground">None archived.</p>}
          </div>
        </details>
      )}
    </div>
  );
}
