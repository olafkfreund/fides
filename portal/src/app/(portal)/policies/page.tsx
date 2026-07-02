"use client";

import { useEffect, useState } from "react";
import { Plus, Trash2, Save, Sparkles, Info, Loader2 } from "lucide-react";
import { apiGet, apiPost, api } from "@/lib/api";

// The /api/v1/policies list returns rules in `yaml` and the description in `target`
// (legacy field names). Keep the aliases optional and map them on read.
type Policy = { id: string; name: string; target?: string; yaml?: string };

const input = "w-full rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground";
const mono = "w-full rounded-md border border-border bg-background px-3 py-2 text-sm font-mono text-foreground";

export default function Policies() {
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [sel, setSel] = useState<Policy | null>(null);
  const [mode, setMode] = useState<"view" | "new">("view");
  const [editRules, setEditRules] = useState("");
  const [wName, setWName] = useState(""); const [wFramework, setWFramework] = useState("SOC2");
  const [wDesc, setWDesc] = useState(""); const [wRules, setWRules] = useState("");
  const [generating, setGenerating] = useState(false);
  const [msg, setMsg] = useState<{ t: string; ok: boolean }>({ t: "", ok: true });

  const load = () => apiGet<Policy[]>("/api/v1/policies").then((p) => setPolicies(p || [])).catch((e) => setMsg({ t: String(e.message), ok: false }));
  useEffect(() => { load(); }, []);

  const select = (p: Policy) => { setSel(p); setMode("view"); setEditRules(p.yaml || ""); setMsg({ t: "", ok: true }); };

  const saveRules = async () => {
    if (!sel) return;
    try { await api("POST", "/api/v1/policies", { id: sel.id, yaml: editRules }); setMsg({ t: "Saved.", ok: true }); load(); }
    catch (e) { setMsg({ t: String((e as Error).message), ok: false }); }
  };
  const del = async () => {
    if (!sel) return;
    try { await api("DELETE", `/api/v1/policies/${sel.id}`); setSel(null); setMsg({ t: "Deleted.", ok: true }); load(); }
    catch (e) { setMsg({ t: String((e as Error).message), ok: false }); }
  };

  const generate = async () => {
    setGenerating(true); setMsg({ t: "", ok: true });
    try {
      const r = await apiPost<unknown>("/api/v1/ai/generate-policy", { framework: wFramework, description: wDesc });
      setWRules(typeof r === "string" ? r : JSON.stringify(r, null, 2));
    } catch (e) { setMsg({ t: "AI generation failed: " + String((e as Error).message), ok: false }); }
    finally { setGenerating(false); }
  };
  const create = async () => {
    try {
      await apiPost("/api/v1/policies/create", { name: wName, description: wDesc, rules: wRules });
      setWName(""); setWDesc(""); setWRules(""); setMode("view"); setMsg({ t: "Policy created.", ok: true }); load();
    } catch (e) { setMsg({ t: String((e as Error).message), ok: false }); }
  };

  return (
    <div>
      <h1 className="text-xl font-semibold">Policies</h1>
      <p className="mt-1 text-sm text-muted-foreground">Deterministic compliance gates evaluated with jq rules.</p>

      <div className="mt-4 flex items-start gap-2 rounded-md bg-muted/50 p-3 text-xs text-muted-foreground">
        <Info className="mt-0.5 size-4 shrink-0 text-primary" />
        <span>A <strong>policy</strong> is a named set of rules that decide whether a build is compliant — e.g. &ldquo;no critical CVEs&rdquo; or &ldquo;unit tests pass&rdquo;. Rules are jq expressions evaluated against attestation evidence. Use the <strong>wizard</strong> to draft one (optionally with AI), then edit or delete anytime.</span>
      </div>

      <div className="mt-6 grid grid-cols-1 gap-5 lg:grid-cols-[280px_1fr]">
        <div className="rounded-xl border border-border bg-card p-3">
          <button onClick={() => { setMode("new"); setSel(null); }} className="mb-2 flex w-full items-center justify-center gap-1.5 rounded-md bg-primary px-3 py-2 text-sm font-semibold text-primary-foreground">
            <Plus className="size-4" /> New Policy
          </button>
          {policies.length ? policies.map((p) => (
            <button key={p.id} onClick={() => select(p)} className={`mb-1 block w-full rounded-md px-3 py-2 text-left text-sm ${sel?.id === p.id ? "bg-primary/15 font-medium text-foreground" : "text-muted-foreground hover:bg-accent hover:text-foreground"}`}>
              <div className="font-mono">{p.name}</div>
              {p.target && <div className="truncate text-xs text-muted-foreground">{p.target}</div>}
            </button>
          )) : <p className="p-3 text-sm text-muted-foreground">No policies yet.</p>}
        </div>

        <div className="rounded-xl border border-border bg-card p-5">
          {mode === "new" ? (
            <>
              <h2 className="text-sm font-semibold">New policy</h2>
              <div className="mt-4 grid grid-cols-1 gap-3 sm:grid-cols-2">
                <label className="text-sm"><span className="text-muted-foreground">Name</span><input className={input} value={wName} onChange={(e) => setWName(e.target.value)} placeholder="production-release-rules" /></label>
                <label className="text-sm"><span className="text-muted-foreground">Framework</span>
                  <select className={input} value={wFramework} onChange={(e) => setWFramework(e.target.value)}><option>SOC2</option><option>ISO27001</option><option>FDA-21CFR11</option><option>PCI-DSS</option><option>Custom</option></select>
                </label>
              </div>
              <label className="mt-3 block text-sm"><span className="text-muted-foreground">What should this policy enforce?</span>
                <textarea className={`${input} h-20`} value={wDesc} onChange={(e) => setWDesc(e.target.value)} placeholder="e.g. block releases with critical CVEs and require passing unit tests and an SBOM" />
              </label>
              <div className="mt-3">
                <button onClick={generate} disabled={generating || !wDesc} className="flex items-center gap-1.5 rounded-md border border-primary/40 bg-primary/10 px-4 py-2 text-sm font-semibold text-primary disabled:opacity-50">
                  {generating ? <Loader2 className="size-4 animate-spin" /> : <Sparkles className="size-4" />} {generating ? "Generating…" : "Draft rules with AI"}
                </button>
              </div>
              <label className="mt-4 block text-sm"><span className="text-muted-foreground">Rules (review &amp; edit)</span>
                <textarea className={`${mono} h-56`} value={wRules} onChange={(e) => setWRules(e.target.value)} placeholder='{"controls":[{"name":"no-critical-cves","attestation_type":"snyk-scan","jq_expressions":[".vulnerabilities.critical == 0"]}]}' />
              </label>
              <div className="mt-4 flex items-center gap-3">
                <button onClick={create} disabled={!wName} className="rounded-md bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground disabled:opacity-50">Create policy</button>
                <button onClick={() => setMode("view")} className="rounded-md border border-border px-4 py-2 text-sm">Cancel</button>
                {msg.t && <span className={`text-sm ${msg.ok ? "text-green-400" : "text-red-400"}`}>{msg.t}</span>}
              </div>
            </>
          ) : sel ? (
            <>
              <div className="flex items-start justify-between">
                <div><div className="font-mono font-semibold">{sel.name}</div>{sel.target && <div className="text-xs text-muted-foreground">{sel.target}</div>}</div>
                <button onClick={del} className="flex items-center gap-1.5 rounded-md border border-red-500/40 px-3 py-1.5 text-xs text-red-400 hover:bg-red-500/10"><Trash2 className="size-3.5" /> Delete</button>
              </div>
              <label className="mt-4 block text-sm"><span className="text-muted-foreground">Rules (jq)</span>
                <textarea className={`${mono} h-64`} value={editRules} onChange={(e) => setEditRules(e.target.value)} />
              </label>
              <div className="mt-3 flex items-center gap-3">
                <button onClick={saveRules} className="flex items-center gap-1.5 rounded-md bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground"><Save className="size-4" /> Save rules</button>
                {msg.t && <span className={`text-sm ${msg.ok ? "text-green-400" : "text-red-400"}`}>{msg.t}</span>}
              </div>
            </>
          ) : <p className="text-sm text-muted-foreground">Select a policy, or create a new one.</p>}
        </div>
      </div>
    </div>
  );
}
