"use client";

import { useEffect, useState } from "react";
import { CheckCircle2, XCircle, RefreshCw, Info, ChevronDown, ChevronRight, Loader2 } from "lucide-react";
import { apiGet, apiPost } from "@/lib/api";

type RuntimeArtifact = { service: string; sha256: string; registered: boolean; name: string };
type Env = {
  id: string; name: string; type: string; description?: string;
  lastSnapshot?: string; running?: RuntimeArtifact[]; drifts?: string[]; shadowChanges?: string[];
};
type MCPConn = { id: string; name: string; transport: string; command?: string };
type Verdict = { compliant: boolean; failed_rules?: string[]; raw_response?: string };
type Check = { loading: boolean; verdict?: Verdict; error?: string };
type Approval = { artifact_sha256: string; approved_by?: string; reason?: string };

// Fides auto-runs this readiness compliance check against each MCP connection.
const DEFAULT_TOOL = "get_pods";
const DEFAULT_RULES = ['.pods[].status == "Ready"', ".pods[].replicas == .pods[].readyReplicas"];

const input = "w-full rounded-md border border-border bg-background px-3 py-2 text-sm font-mono text-foreground";
const panel = "rounded-xl border border-border bg-card p-5";

export default function Environments() {
  const [envs, setEnvs] = useState<Env[]>([]);
  const [sel, setSel] = useState("");
  const [filter, setFilter] = useState("");
  const [conns, setConns] = useState<MCPConn[]>([]);
  const [checks, setChecks] = useState<Record<string, Check>>({});
  const [allow, setAllow] = useState<Approval[]>([]);
  const [advanced, setAdvanced] = useState(false);
  // advanced / manual
  const [server, setServer] = useState(""); const [tool, setTool] = useState("get_pods");
  const [rules, setRules] = useState(DEFAULT_RULES.join("\n"));
  const [verdict, setVerdict] = useState<Verdict | null>(null); const [queryOut, setQueryOut] = useState("");
  const [mName, setMName] = useState(""); const [mTransport, setMTransport] = useState("stdio");
  const [mCommand, setMCommand] = useState(""); const [mUrl, setMUrl] = useState("");
  const [sha, setSha] = useState(""); const [reason, setReason] = useState("");
  const [err, setErr] = useState("");

  useEffect(() => {
    apiGet<Env[]>("/api/v1/environments").then((e) => { setEnvs(e); if (e.length) setSel(e[0].id); }).catch((x) => setErr(String(x.message || x)));
  }, []);

  // On environment change: load connections + allow-list, then AUTO-RUN compliance checks.
  const runChecks = async (id: string, list: MCPConn[]) => {
    for (const c of list) {
      setChecks((m) => ({ ...m, [c.name]: { loading: true } }));
      try {
        const v = await apiPost<Verdict>("/api/v1/environments/mcp/verify", {
          environment_id: id, server_name: c.name, tool_name: DEFAULT_TOOL, arguments: {}, rules: DEFAULT_RULES,
        });
        setChecks((m) => ({ ...m, [c.name]: { loading: false, verdict: v } }));
      } catch (e) {
        setChecks((m) => ({ ...m, [c.name]: { loading: false, error: String((e as Error).message || e) } }));
      }
    }
  };

  const loadEnv = (id: string) => {
    setChecks({}); setServer("");
    apiGet<MCPConn[]>(`/api/v1/environments/mcp?environment_id=${id}`).then((c) => {
      const list = c || [];
      setConns(list);
      if (list.length) setServer(list[0].name);
      runChecks(id, list);
    }).catch(() => setConns([]));
    apiGet<Approval[]>(`/api/v1/environments/${id}/allowlist`).then((a) => setAllow(a || [])).catch(() => setAllow([]));
  };

  useEffect(() => { if (sel) loadEnv(sel); }, [sel]); // eslint-disable-line react-hooks/exhaustive-deps

  const runManualVerify = async () => {
    setErr("");
    try {
      setVerdict(await apiPost<Verdict>("/api/v1/environments/mcp/verify", {
        environment_id: sel, server_name: server, tool_name: tool, arguments: {},
        rules: rules.split("\n").map((s) => s.trim()).filter(Boolean),
      }));
    } catch (e) { setErr(String((e as Error).message || e)); }
  };
  const runQuery = async () => {
    setErr(""); setQueryOut("");
    try {
      const r = await apiPost<{ raw_response?: string }>("/api/v1/environments/mcp/query", { environment_id: sel, server_name: server, tool_name: tool, arguments: {} });
      setQueryOut(typeof r === "string" ? r : (r.raw_response ?? JSON.stringify(r, null, 2)));
    } catch (e) { setErr(String((e as Error).message || e)); }
  };
  const addMcp = async () => {
    setErr("");
    try {
      await apiPost("/api/v1/environments/mcp", { environment_id: sel, name: mName, transport: mTransport, command: mCommand, args: [], env_vars: {}, url: mUrl, auth_header: "" });
      setMName(""); setMCommand(""); setMUrl(""); loadEnv(sel);
    } catch (e) { setErr(String((e as Error).message || e)); }
  };
  const addAllow = async () => {
    setErr("");
    try {
      await apiPost(`/api/v1/environments/${sel}/allowlist`, { artifact_sha256: sha, reason });
      setSha(""); setReason(""); setAllow(await apiGet<Approval[]>(`/api/v1/environments/${sel}/allowlist`));
    } catch (e) { setErr(String((e as Error).message || e)); }
  };

  const overall = conns.map((c) => checks[c.name]?.verdict).filter(Boolean);
  const allCompliant = overall.length > 0 && overall.every((v) => v!.compliant);

  return (
    <div className="max-w-4xl">
      <h1 className="text-xl font-semibold">Environments</h1>
      <p className="mt-1 text-sm text-muted-foreground">Runtime compliance, verified automatically against your MCP-connected clusters.</p>

      <div className="mt-6 flex flex-col gap-5">
        {/* Runtime environments */}
        <div className={panel}>
          <div className="mb-3 flex items-center justify-between">
            <h2 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">Runtime Environments</h2>
            <input className="w-56 rounded-md border border-border bg-background px-3 py-1.5 text-sm" value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="Filter by name…" />
          </div>
          <div className="flex flex-col gap-2">
            {envs.filter((e) => e.name.toLowerCase().includes(filter.toLowerCase())).map((e) => {
              const drifts = e.drifts?.length ?? 0, shadows = e.shadowChanges?.length ?? 0, running = e.running?.length ?? 0;
              const secure = drifts === 0 && shadows === 0;
              return (
                <button key={e.id} onClick={() => setSel(e.id)} className={`rounded-md border p-3 text-left ${sel === e.id ? "border-primary/50 bg-primary/5" : "border-border hover:bg-accent/40"}`}>
                  <div className="flex items-start justify-between">
                    <div>
                      <span className="font-semibold">{e.name}</span>
                      <span className="ml-2 rounded bg-muted px-2 py-0.5 text-xs uppercase text-muted-foreground">{e.type}</span>
                      {e.description && <div className="mt-0.5 text-xs text-muted-foreground">{e.description}</div>}
                    </div>
                    <span className={`rounded px-2 py-0.5 text-xs font-medium ${secure ? "bg-green-500/15 text-green-400" : "bg-amber-500/15 text-amber-400"}`}>{secure ? "SECURE" : "DRIFT"}</span>
                  </div>
                  <div className="mt-2 flex flex-wrap gap-4 text-xs text-muted-foreground">
                    <span><span className="text-foreground">{running}</span> running</span>
                    <span><span className={drifts ? "text-amber-400" : "text-foreground"}>{drifts}</span> drifts</span>
                    <span><span className={shadows ? "text-amber-400" : "text-foreground"}>{shadows}</span> shadows</span>
                    <span>last snapshot: {e.lastSnapshot || "—"}</span>
                  </div>
                </button>
              );
            })}
            {envs.length === 0 && <p className="text-sm text-muted-foreground">No environments.</p>}
          </div>
        </div>

        {/* Automatic MCP compliance */}
        <div className={panel}>
          <div className="mb-2 flex items-center justify-between">
            <h2 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">Live Compliance — {envs.find((e) => e.id === sel)?.name || "…"}</h2>
            <div className="flex items-center gap-3">
              {overall.length > 0 && <span className={`rounded px-2 py-0.5 text-xs font-medium ${allCompliant ? "bg-green-500/15 text-green-400" : "bg-red-500/15 text-red-400"}`}>{allCompliant ? "ALL COMPLIANT" : "ISSUES FOUND"}</span>}
              <button onClick={() => loadEnv(sel)} className="flex items-center gap-1.5 rounded-md border border-border px-3 py-1.5 text-xs"><RefreshCw className="size-3.5" /> Re-run</button>
            </div>
          </div>
          <p className="mb-4 flex items-start gap-2 rounded-md bg-muted/50 p-3 text-xs text-muted-foreground">
            <Info className="mt-0.5 size-4 shrink-0 text-primary" />
            <span>Fides connects to this environment&apos;s <strong>MCP servers</strong> (e.g. the in-cluster <code className="rounded bg-muted px-1">fides-mcp-sensor</code>) and automatically runs runtime compliance checks — no queries to write. Each connection below is checked for workload readiness on load.</span>
          </p>

          {conns.length === 0 ? (
            <p className="text-sm text-muted-foreground">No MCP connections for this environment. Add one under Advanced below.</p>
          ) : (
            <div className="flex flex-col gap-2">
              {conns.map((c) => {
                const ch = checks[c.name];
                return (
                  <div key={c.id} className="rounded-md border border-border p-3">
                    <div className="flex items-center justify-between">
                      <span className="flex items-center gap-2 text-sm font-medium">
                        {ch?.loading ? <Loader2 className="size-4 animate-spin text-muted-foreground" /> : ch?.verdict ? (ch.verdict.compliant ? <CheckCircle2 className="size-4 text-green-400" /> : <XCircle className="size-4 text-red-400" />) : <XCircle className="size-4 text-muted-foreground" />}
                        {c.name} <span className="text-xs font-normal text-muted-foreground">({c.transport})</span>
                      </span>
                      <span className={`text-xs font-medium ${ch?.loading ? "text-muted-foreground" : ch?.verdict ? (ch.verdict.compliant ? "text-green-400" : "text-red-400") : "text-muted-foreground"}`}>
                        {ch?.loading ? "checking…" : ch?.verdict ? (ch.verdict.compliant ? "COMPLIANT" : "NON-COMPLIANT") : ch?.error ? "unreachable" : "—"}
                      </span>
                    </div>
                    {ch?.verdict && !ch.verdict.compliant && (ch.verdict.failed_rules?.length ?? 0) > 0 && (
                      <div className="mt-1.5 text-xs text-red-400">failed: {ch.verdict.failed_rules!.join("  |  ")}</div>
                    )}
                    {ch?.error && <div className="mt-1.5 text-xs text-muted-foreground">{ch.error}</div>}
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Approved artifacts */}
        <div className={panel}>
          <h2 className="mb-3 text-xs font-semibold uppercase tracking-wide text-muted-foreground">Approved Artifacts (allow-list)</h2>
          {allow.length > 0 ? (
            <table className="w-full text-left text-xs font-mono">
              <thead className="text-muted-foreground"><tr><th className="py-1">SHA256</th><th>By</th><th>Reason</th></tr></thead>
              <tbody>{allow.map((a, i) => <tr key={i} className="border-t border-border"><td className="py-1 break-all">{a.artifact_sha256}</td><td>{a.approved_by}</td><td>{a.reason}</td></tr>)}</tbody>
            </table>
          ) : <p className="text-sm text-muted-foreground">No approvals.</p>}
          <div className="mt-3 flex flex-wrap items-center gap-2">
            <input className={`${input} w-72`} value={sha} onChange={(e) => setSha(e.target.value)} placeholder="artifact SHA256 to approve" />
            <input className={`${input} w-48`} value={reason} onChange={(e) => setReason(e.target.value)} placeholder="reason" />
            <button onClick={addAllow} className="rounded-md bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground">Approve</button>
            <a href="/api/v1/environments/export" className="ml-auto rounded-md border border-border px-4 py-2 text-sm">Download Audit Report</a>
          </div>
        </div>

        {/* Advanced */}
        <div className={panel}>
          <button onClick={() => setAdvanced((a) => !a)} className="flex w-full items-center gap-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
            {advanced ? <ChevronDown className="size-4" /> : <ChevronRight className="size-4" />} Advanced — custom check &amp; add connection
          </button>
          {advanced && (
            <div className="mt-4 flex flex-col gap-4">
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                <label className="text-sm"><span className="text-muted-foreground">Connection</span>
                  <select className={input} value={server} onChange={(e) => setServer(e.target.value)}>{conns.map((c) => <option key={c.id} value={c.name}>{c.name}</option>)}</select>
                </label>
                <label className="text-sm"><span className="text-muted-foreground">Tool</span><input className={input} value={tool} onChange={(e) => setTool(e.target.value)} /></label>
              </div>
              <label className="text-sm"><span className="text-muted-foreground">Compliance jq rules (one per line)</span><textarea className={`${input} h-24`} value={rules} onChange={(e) => setRules(e.target.value)} /></label>
              <div className="flex gap-2">
                <button onClick={runManualVerify} className="rounded-md bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground">Verify</button>
                <button onClick={runQuery} className="rounded-md border border-border px-4 py-2 text-sm">Query State</button>
              </div>
              {verdict && <div className={`text-sm font-semibold ${verdict.compliant ? "text-green-400" : "text-red-400"}`}>{verdict.compliant ? "✅ COMPLIANT" : `❌ NON-COMPLIANT — ${(verdict.failed_rules || []).join(" | ")}`}</div>}
              {queryOut && <pre className="overflow-auto rounded-md border border-border bg-background p-3 text-xs text-foreground">{queryOut}</pre>}
              <div className="border-t border-border pt-4">
                <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">Add MCP connection</h3>
                <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                  <input className={input} value={mName} onChange={(e) => setMName(e.target.value)} placeholder="name (aws-sensor)" />
                  <select className={input} value={mTransport} onChange={(e) => setMTransport(e.target.value)}><option value="stdio">stdio</option><option value="http">http</option></select>
                  <input className={input} value={mCommand} onChange={(e) => setMCommand(e.target.value)} placeholder="command (fides-mcp-sensor) — stdio" />
                  <input className={input} value={mUrl} onChange={(e) => setMUrl(e.target.value)} placeholder="url — http" />
                </div>
                <button onClick={addMcp} disabled={!mName} className="mt-3 rounded-md bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground disabled:opacity-50">Add MCP Server</button>
              </div>
            </div>
          )}
        </div>

        {err && <p className="text-sm text-red-400">{err}</p>}
      </div>
    </div>
  );
}
