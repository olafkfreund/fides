"use client";

import { useEffect, useState } from "react";
import { apiGet, apiPost } from "@/lib/api";

type RuntimeArtifact = { service: string; sha256: string; registered: boolean; name: string };
type Env = {
  id: string; name: string; type: string; description?: string;
  lastSnapshot?: string; running?: RuntimeArtifact[]; drifts?: string[]; shadowChanges?: string[];
};
type MCPConn = { id: string; name: string; transport: string; command?: string };
type Verdict = { compliant: boolean; failed_rules?: string[]; raw_response?: string };
type Approval = { artifact_sha256: string; approved_by?: string; reason?: string };

const input = "w-full rounded-md border border-border bg-background px-3 py-2 text-sm font-mono text-foreground";
const panel = "rounded-xl border border-border bg-card p-5";

export default function Environments() {
  const [envs, setEnvs] = useState<Env[]>([]);
  const [sel, setSel] = useState("");
  const [conns, setConns] = useState<MCPConn[]>([]);
  const [tool, setTool] = useState("get_pods");
  const [server, setServer] = useState("");
  const [rules, setRules] = useState('.pods[].status == "Ready"\n.pods[].replicas == .pods[].readyReplicas');
  const [verdict, setVerdict] = useState<Verdict | null>(null);
  const [allow, setAllow] = useState<Approval[]>([]);
  const [sha, setSha] = useState("");
  const [reason, setReason] = useState("");
  const [queryOut, setQueryOut] = useState("");
  const [mName, setMName] = useState(""); const [mTransport, setMTransport] = useState("stdio");
  const [mCommand, setMCommand] = useState(""); const [mUrl, setMUrl] = useState("");
  const [filter, setFilter] = useState("");
  const [err, setErr] = useState("");

  useEffect(() => {
    apiGet<Env[]>("/api/v1/environments").then((e) => {
      setEnvs(e);
      if (e.length) setSel(e[0].id);
    }).catch((x) => setErr(String(x.message || x)));
  }, []);

  useEffect(() => {
    if (!sel) return;
    apiGet<MCPConn[]>(`/api/v1/environments/mcp?environment_id=${sel}`).then((c) => {
      setVerdict(null);
      setConns(c || []);
      if (c && c.length) setServer(c[0].name);
    }).catch(() => setConns([]));
    apiGet<Approval[]>(`/api/v1/environments/${sel}/allowlist`).then((a) => setAllow(a || [])).catch(() => setAllow([]));
  }, [sel]);

  const runVerify = async () => {
    setErr("");
    try {
      const r = await apiPost<Verdict>("/api/v1/environments/mcp/verify", {
        environment_id: sel, server_name: server, tool_name: tool, arguments: {},
        rules: rules.split("\n").map((s) => s.trim()).filter(Boolean),
      });
      setVerdict(r);
    } catch (e) { setErr(String((e as Error).message || e)); }
  };

  const runQuery = async () => {
    setErr(""); setQueryOut("");
    try {
      const r = await apiPost<{ raw_response?: string }>("/api/v1/environments/mcp/query", {
        environment_id: sel, server_name: server, tool_name: tool, arguments: {},
      });
      setQueryOut(typeof r === "string" ? r : (r.raw_response ?? JSON.stringify(r, null, 2)));
    } catch (e) { setErr(String((e as Error).message || e)); }
  };

  const loadConns = () => apiGet<MCPConn[]>(`/api/v1/environments/mcp?environment_id=${sel}`).then((c) => setConns(c || [])).catch(() => {});

  const addMcp = async () => {
    setErr("");
    try {
      await apiPost("/api/v1/environments/mcp", {
        environment_id: sel, name: mName, transport: mTransport,
        command: mCommand, args: [], env_vars: {}, url: mUrl, auth_header: "",
      });
      setMName(""); setMCommand(""); setMUrl(""); loadConns();
    } catch (e) { setErr(String((e as Error).message || e)); }
  };

  const addAllow = async () => {
    setErr("");
    try {
      await apiPost(`/api/v1/environments/${sel}/allowlist`, { artifact_sha256: sha, reason });
      setSha(""); setReason("");
      setAllow(await apiGet<Approval[]>(`/api/v1/environments/${sel}/allowlist`));
    } catch (e) { setErr(String((e as Error).message || e)); }
  };

  return (
    <div className="max-w-4xl">
      <h1 className="text-xl font-semibold">Environments</h1>
      <p className="mt-1 text-sm text-muted-foreground">Runtime compliance verification and artifact approvals.</p>

      <div className="mt-6 flex flex-col gap-5">
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
                <div key={e.id} className="rounded-md border border-border p-3">
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
                </div>
              );
            })}
            {envs.length === 0 && <p className="text-sm text-muted-foreground">No environments.</p>}
          </div>
        </div>

        <div className={panel}>
          <div className="flex items-end justify-between gap-4">
            <label className="flex-1 text-sm">
              <span className="text-muted-foreground">Environment</span>
              <select className={input} value={sel} onChange={(e) => setSel(e.target.value)}>
                {envs.map((e) => <option key={e.id} value={e.id}>{e.name} ({e.type})</option>)}
              </select>
            </label>
            <a href="/api/v1/environments/export" className="whitespace-nowrap rounded-md border border-border px-4 py-2 text-sm">Download Audit Report</a>
          </div>
        </div>

        <div className={panel}>
          <h2 className="mb-3 text-xs font-semibold uppercase tracking-wide text-muted-foreground">Add MCP connection</h2>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <input className={input} value={mName} onChange={(e) => setMName(e.target.value)} placeholder="name (aws-sensor)" />
            <select className={input} value={mTransport} onChange={(e) => setMTransport(e.target.value)}><option value="stdio">stdio</option><option value="http">http</option></select>
            <input className={input} value={mCommand} onChange={(e) => setMCommand(e.target.value)} placeholder="command (fides-mcp-sensor) — stdio" />
            <input className={input} value={mUrl} onChange={(e) => setMUrl(e.target.value)} placeholder="url — http" />
          </div>
          <div className="mt-3"><button onClick={addMcp} disabled={!mName} className="rounded-md bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground disabled:opacity-50">Add MCP Server</button></div>
        </div>

        <div className={panel}>
          <h2 className="mb-3 text-xs font-semibold uppercase tracking-wide text-muted-foreground">MCP compliance check</h2>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <label className="text-sm"><span className="text-muted-foreground">Connection</span>
              <select className={input} value={server} onChange={(e) => setServer(e.target.value)}>
                {conns.map((c) => <option key={c.id} value={c.name}>{c.name} ({c.transport})</option>)}
              </select>
            </label>
            <label className="text-sm"><span className="text-muted-foreground">Tool</span>
              <input className={input} value={tool} onChange={(e) => setTool(e.target.value)} />
            </label>
          </div>
          <label className="mt-3 block text-sm"><span className="text-muted-foreground">Compliance jq rules (one per line)</span>
            <textarea className={`${input} h-24`} value={rules} onChange={(e) => setRules(e.target.value)} />
          </label>
          <div className="mt-3 flex gap-3">
            <button onClick={runVerify} className="rounded-md bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground">Verify Compliance</button>
            <button onClick={runQuery} className="rounded-md border border-border px-4 py-2 text-sm">Query State</button>
          </div>
          {queryOut && <pre className="mt-3 overflow-auto rounded-md border border-border bg-background p-3 text-xs text-foreground">{queryOut}</pre>}
          {verdict && (
            <div className="mt-4">
              <div className={`text-sm font-semibold ${verdict.compliant ? "text-green-400" : "text-red-400"}`}>
                {verdict.compliant ? "✅ COMPLIANT" : `❌ NON-COMPLIANT — failed: ${(verdict.failed_rules || []).join("  |  ")}`}
              </div>
              {verdict.raw_response && <pre className="mt-2 overflow-auto rounded-md border border-border bg-background p-3 text-xs text-green-400">{verdict.raw_response}</pre>}
            </div>
          )}
        </div>

        <div className={panel}>
          <h2 className="mb-3 text-xs font-semibold uppercase tracking-wide text-muted-foreground">Approved artifacts (allow-list)</h2>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <label className="text-sm"><span className="text-muted-foreground">Artifact SHA256</span><input className={input} value={sha} onChange={(e) => setSha(e.target.value)} /></label>
            <label className="text-sm"><span className="text-muted-foreground">Reason</span><input className={input} value={reason} onChange={(e) => setReason(e.target.value)} /></label>
          </div>
          <div className="mt-3"><button onClick={addAllow} className="rounded-md bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground">Approve</button></div>
          {allow.length > 0 ? (
            <table className="mt-4 w-full text-left text-xs font-mono">
              <thead className="text-muted-foreground"><tr><th className="py-1">SHA256</th><th>By</th><th>Reason</th></tr></thead>
              <tbody>{allow.map((a, i) => <tr key={i} className="border-t border-border"><td className="py-1">{a.artifact_sha256}</td><td>{a.approved_by}</td><td>{a.reason}</td></tr>)}</tbody>
            </table>
          ) : <p className="mt-3 text-sm text-muted-foreground">No approvals.</p>}
        </div>

        {err && <p className="text-sm text-red-400">{err}</p>}
      </div>
    </div>
  );
}
