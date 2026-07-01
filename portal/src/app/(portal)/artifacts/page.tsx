"use client";

import { useEffect, useState } from "react";
import { apiGet } from "@/lib/api";

type Artifact = { sha256: string; name: string; type: string; git_commit?: string; created_at?: string };
type Attestation = { id: string; name: string; type_name: string; is_compliant: boolean; trail_id: string };

const input = "w-full rounded-md border border-neutral-800 bg-neutral-950 px-3 py-2 text-sm font-mono text-neutral-200";
const panel = "rounded-xl border border-neutral-800 bg-neutral-900 p-5";

export default function Artifacts() {
  const [sha, setSha] = useState("");
  const [name, setName] = useState("");
  const [arts, setArts] = useState<Artifact[]>([]);
  const [type, setType] = useState("");
  const [compliant, setCompliant] = useState("");
  const [atts, setAtts] = useState<Attestation[]>([]);
  const [err, setErr] = useState("");

  const searchArts = () => {
    const q = new URLSearchParams();
    if (sha) q.set("sha", sha);
    if (name) q.set("name", name);
    apiGet<Artifact[]>(`/api/v1/search/artifacts?${q}`).then(setArts).catch((e) => setErr(String(e.message || e)));
  };
  const searchAtts = () => {
    const q = new URLSearchParams();
    if (type) q.set("type", type);
    if (compliant) q.set("compliant", compliant);
    apiGet<Attestation[]>(`/api/v1/search/attestations?${q}`).then(setAtts).catch((e) => setErr(String(e.message || e)));
  };
  useEffect(() => { searchArts(); }, []); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <div className="max-w-5xl">
      <h1 className="text-xl font-semibold">Artifacts &amp; SBOM</h1>
      <p className="mt-1 text-sm text-neutral-500">Search build artifacts and their attestations.</p>

      <div className="mt-6 flex flex-col gap-5">
        <div className={panel}>
          <h2 className="mb-3 text-xs font-semibold uppercase tracking-wide text-neutral-500">Artifacts</h2>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
            <input className={input} value={sha} onChange={(e) => setSha(e.target.value)} placeholder="SHA256 prefix" />
            <input className={input} value={name} onChange={(e) => setName(e.target.value)} placeholder="name" />
            <button onClick={searchArts} className="rounded-md bg-purple-600 px-4 py-2 text-sm font-semibold text-white">Search</button>
          </div>
          {arts.length > 0 ? (
            <table className="mt-4 w-full text-left text-xs font-mono">
              <thead className="text-neutral-500"><tr><th className="py-1">SHA256</th><th>Name</th><th>Type</th><th>Commit</th></tr></thead>
              <tbody>{arts.map((a) => <tr key={a.sha256} className="border-t border-neutral-800"><td className="py-1">{a.sha256.slice(0, 20)}…</td><td>{a.name}</td><td>{a.type}</td><td>{a.git_commit?.slice(0, 10)}</td></tr>)}</tbody>
            </table>
          ) : <p className="mt-3 text-sm text-neutral-500">No results.</p>}
        </div>

        <div className={panel}>
          <h2 className="mb-3 text-xs font-semibold uppercase tracking-wide text-neutral-500">Attestations</h2>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
            <input className={input} value={type} onChange={(e) => setType(e.target.value)} placeholder="type (junit, snyk…)" />
            <select className={input} value={compliant} onChange={(e) => setCompliant(e.target.value)}>
              <option value="">any compliance</option><option value="true">compliant</option><option value="false">non-compliant</option>
            </select>
            <button onClick={searchAtts} className="rounded-md bg-purple-600 px-4 py-2 text-sm font-semibold text-white">Search</button>
          </div>
          {atts.length > 0 ? (
            <table className="mt-4 w-full text-left text-xs font-mono">
              <thead className="text-neutral-500"><tr><th className="py-1">Name</th><th>Type</th><th>Compliant</th></tr></thead>
              <tbody>{atts.map((a) => <tr key={a.id} className="border-t border-neutral-800"><td className="py-1">{a.name}</td><td>{a.type_name}</td><td className={a.is_compliant ? "text-green-400" : "text-red-400"}>{a.is_compliant ? "yes" : "no"}</td></tr>)}</tbody>
            </table>
          ) : <p className="mt-3 text-sm text-neutral-500">Run a search.</p>}
        </div>

        {err && <p className="text-sm text-red-400">{err}</p>}
      </div>
    </div>
  );
}
