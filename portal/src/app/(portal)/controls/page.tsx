"use client";

import { useEffect, useState } from "react";
import { apiGet, apiPost } from "@/lib/api";

type Control = { id: string; key: string; name: string; framework?: string; required_types?: string[] };
type Coverage = { total_environments: number; controls: { control: string; name: string; enforced_in: string[]; coverage: number }[] };

const input = "w-full rounded-md border border-neutral-800 bg-neutral-950 px-3 py-2 text-sm font-mono text-neutral-200";
const panel = "rounded-xl border border-neutral-800 bg-neutral-900 p-5";

export default function Controls() {
  const [controls, setControls] = useState<Control[]>([]);
  const [cov, setCov] = useState<Coverage | null>(null);
  const [key, setKey] = useState("");
  const [name, setName] = useState("");
  const [framework, setFramework] = useState("SOC2");
  const [require, setRequire] = useState("");
  const [err, setErr] = useState("");

  const load = () => {
    apiGet<Control[]>("/api/v1/controls").then(setControls).catch((e) => setErr(String(e.message || e)));
    apiGet<Coverage>("/api/v1/controls/coverage").then(setCov).catch(() => {});
  };
  useEffect(() => { load(); }, []);

  const add = async () => {
    setErr("");
    try {
      await apiPost("/api/v1/controls", {
        key, name, framework,
        required_types: require.split(",").map((s) => s.trim()).filter(Boolean),
      });
      setKey(""); setName(""); setRequire("");
      load();
    } catch (e) { setErr(String((e as Error).message || e)); }
  };

  return (
    <div className="max-w-4xl">
      <h1 className="text-xl font-semibold">Controls &amp; Coverage</h1>
      <p className="mt-1 text-sm text-neutral-500">Governance controls mapping to attestation types, and per-environment coverage.</p>

      <div className="mt-6 flex flex-col gap-5">
        <div className={panel}>
          <h2 className="mb-3 text-xs font-semibold uppercase tracking-wide text-neutral-500">Add control</h2>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <input className={input} value={key} onChange={(e) => setKey(e.target.value)} placeholder="key (SOC2-CC7.1)" />
            <input className={input} value={name} onChange={(e) => setName(e.target.value)} placeholder="name" />
            <input className={input} value={framework} onChange={(e) => setFramework(e.target.value)} placeholder="framework" />
            <input className={input} value={require} onChange={(e) => setRequire(e.target.value)} placeholder="required types (trivy,snyk)" />
          </div>
          <div className="mt-3"><button onClick={add} className="rounded-md bg-purple-600 px-4 py-2 text-sm font-semibold text-white">Add</button></div>
        </div>

        <div className={panel}>
          <h2 className="mb-3 text-xs font-semibold uppercase tracking-wide text-neutral-500">Coverage {cov ? `(${cov.total_environments} environments)` : ""}</h2>
          {cov && cov.controls.length ? (
            <div className="flex flex-col gap-3">
              {cov.controls.map((c) => (
                <div key={c.control}>
                  <div className="flex items-center justify-between text-sm">
                    <span className="font-mono">{c.control} <span className="text-neutral-500">{c.name}</span></span>
                    <span className="text-neutral-400">{Math.round(c.coverage * 100)}%</span>
                  </div>
                  <div className="mt-1 h-2 w-full rounded-full bg-neutral-800">
                    <div className="h-2 rounded-full bg-purple-500" style={{ width: `${Math.round(c.coverage * 100)}%` }} />
                  </div>
                  {c.enforced_in.length > 0 && <div className="mt-1 text-xs text-neutral-500">enforced in: {c.enforced_in.join(", ")}</div>}
                </div>
              ))}
            </div>
          ) : <p className="text-sm text-neutral-500">No active controls.</p>}
        </div>

        <div className={panel}>
          <h2 className="mb-3 text-xs font-semibold uppercase tracking-wide text-neutral-500">All controls</h2>
          {controls.length ? (
            <table className="w-full text-left text-xs font-mono">
              <thead className="text-neutral-500"><tr><th className="py-1">Key</th><th>Name</th><th>Framework</th><th>Required types</th></tr></thead>
              <tbody>{controls.map((c) => <tr key={c.id} className="border-t border-neutral-800"><td className="py-1">{c.key}</td><td>{c.name}</td><td>{c.framework}</td><td>{(c.required_types || []).join(", ")}</td></tr>)}</tbody>
            </table>
          ) : <p className="text-sm text-neutral-500">No controls yet.</p>}
        </div>

        {err && <p className="text-sm text-red-400">{err}</p>}
      </div>
    </div>
  );
}
