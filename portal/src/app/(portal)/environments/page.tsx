"use client";

import { useEffect, useState } from "react";
import { apiGet, apiPost } from "@/lib/api";

type Env = { id: string; name: string; type: string };
type MCPConn = { id: string; name: string; transport: string; command?: string };
type Verdict = { compliant: boolean; failed_rules?: string[]; raw_response?: string };
type Approval = { artifact_sha256: string; approved_by?: string; reason?: string };

const input = "w-full rounded-md border border-neutral-800 bg-neutral-950 px-3 py-2 text-sm font-mono text-neutral-200";
const panel = "rounded-xl border border-neutral-800 bg-neutral-900 p-5";

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
      <p className="mt-1 text-sm text-neutral-500">Runtime compliance verification and artifact approvals.</p>

      <div className="mt-6 flex flex-col gap-5">
        <div className={panel}>
          <label className="text-sm">
            <span className="text-neutral-500">Environment</span>
            <select className={input} value={sel} onChange={(e) => setSel(e.target.value)}>
              {envs.map((e) => <option key={e.id} value={e.id}>{e.name} ({e.type})</option>)}
            </select>
          </label>
        </div>

        <div className={panel}>
          <h2 className="mb-3 text-xs font-semibold uppercase tracking-wide text-neutral-500">MCP compliance check</h2>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <label className="text-sm"><span className="text-neutral-500">Connection</span>
              <select className={input} value={server} onChange={(e) => setServer(e.target.value)}>
                {conns.map((c) => <option key={c.id} value={c.name}>{c.name} ({c.transport})</option>)}
              </select>
            </label>
            <label className="text-sm"><span className="text-neutral-500">Tool</span>
              <input className={input} value={tool} onChange={(e) => setTool(e.target.value)} />
            </label>
          </div>
          <label className="mt-3 block text-sm"><span className="text-neutral-500">Compliance jq rules (one per line)</span>
            <textarea className={`${input} h-24`} value={rules} onChange={(e) => setRules(e.target.value)} />
          </label>
          <div className="mt-3">
            <button onClick={runVerify} className="rounded-md bg-purple-600 px-4 py-2 text-sm font-semibold text-white">Verify Compliance</button>
          </div>
          {verdict && (
            <div className="mt-4">
              <div className={`text-sm font-semibold ${verdict.compliant ? "text-green-400" : "text-red-400"}`}>
                {verdict.compliant ? "✅ COMPLIANT" : `❌ NON-COMPLIANT — failed: ${(verdict.failed_rules || []).join("  |  ")}`}
              </div>
              {verdict.raw_response && <pre className="mt-2 overflow-auto rounded-md border border-neutral-800 bg-neutral-950 p-3 text-xs text-green-400">{verdict.raw_response}</pre>}
            </div>
          )}
        </div>

        <div className={panel}>
          <h2 className="mb-3 text-xs font-semibold uppercase tracking-wide text-neutral-500">Approved artifacts (allow-list)</h2>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <label className="text-sm"><span className="text-neutral-500">Artifact SHA256</span><input className={input} value={sha} onChange={(e) => setSha(e.target.value)} /></label>
            <label className="text-sm"><span className="text-neutral-500">Reason</span><input className={input} value={reason} onChange={(e) => setReason(e.target.value)} /></label>
          </div>
          <div className="mt-3"><button onClick={addAllow} className="rounded-md bg-purple-600 px-4 py-2 text-sm font-semibold text-white">Approve</button></div>
          {allow.length > 0 ? (
            <table className="mt-4 w-full text-left text-xs font-mono">
              <thead className="text-neutral-500"><tr><th className="py-1">SHA256</th><th>By</th><th>Reason</th></tr></thead>
              <tbody>{allow.map((a, i) => <tr key={i} className="border-t border-neutral-800"><td className="py-1">{a.artifact_sha256}</td><td>{a.approved_by}</td><td>{a.reason}</td></tr>)}</tbody>
            </table>
          ) : <p className="mt-3 text-sm text-neutral-500">No approvals.</p>}
        </div>

        {err && <p className="text-sm text-red-400">{err}</p>}
      </div>
    </div>
  );
}
