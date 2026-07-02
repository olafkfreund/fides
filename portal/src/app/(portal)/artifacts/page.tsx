"use client";

import { useEffect, useState } from "react";
import { apiGet } from "@/lib/api";

type Artifact = { sha256: string; name: string; type: string; git_commit?: string; created_at?: string };
type Attestation = { id: string; name: string; type_name: string; is_compliant: boolean; trail_id: string };

const input = "w-full rounded-md border border-border bg-background px-3 py-2 text-sm font-mono text-foreground";
const panel = "rounded-xl border border-border bg-card p-5";

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
    <div>
      <h1 className="text-xl font-semibold">Artifacts &amp; SBOM</h1>
      <p className="mt-1 text-sm text-muted-foreground">Search build artifacts and their attestations.</p>

      <div className="mt-6 flex flex-col gap-5">
        <div className={panel}>
          <h2 className="mb-3 text-xs font-semibold uppercase tracking-wide text-muted-foreground">Artifacts</h2>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
            <input className={input} value={sha} onChange={(e) => setSha(e.target.value)} placeholder="SHA256 prefix" />
            <input className={input} value={name} onChange={(e) => setName(e.target.value)} placeholder="name" />
            <button onClick={searchArts} className="rounded-md bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground">Search</button>
          </div>
          {arts.length > 0 ? (
            <div className="mt-4 flex flex-col gap-2">
              {arts.map((a) => (
                <div key={a.sha256} className="rounded-md border border-border p-3">
                  <div className="flex flex-wrap items-center justify-between gap-2 text-sm">
                    <span className="font-medium">{a.name} <span className="text-xs text-muted-foreground">· {a.type}</span></span>
                    <span className="font-mono text-xs text-muted-foreground">{a.git_commit ? `commit ${a.git_commit.slice(0, 12)}` : ""}</span>
                  </div>
                  <div className="mt-1.5 flex items-center gap-2">
                    <span className="text-[10px] uppercase tracking-wide text-muted-foreground">sha256</span>
                    <code className="select-all break-all font-mono text-xs text-foreground">{a.sha256}</code>
                    <button onClick={() => navigator.clipboard?.writeText(a.sha256)} className="shrink-0 rounded border border-border px-2 py-0.5 text-[10px] text-muted-foreground hover:text-foreground">Copy</button>
                  </div>
                </div>
              ))}
            </div>
          ) : <p className="mt-3 text-sm text-muted-foreground">No results.</p>}
        </div>

        <div className={panel}>
          <h2 className="mb-3 text-xs font-semibold uppercase tracking-wide text-muted-foreground">Attestations</h2>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
            <input className={input} value={type} onChange={(e) => setType(e.target.value)} placeholder="type (junit, snyk…)" />
            <select className={input} value={compliant} onChange={(e) => setCompliant(e.target.value)}>
              <option value="">any compliance</option><option value="true">compliant</option><option value="false">non-compliant</option>
            </select>
            <button onClick={searchAtts} className="rounded-md bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground">Search</button>
          </div>
          {atts.length > 0 ? (
            <table className="mt-4 w-full text-left text-xs font-mono">
              <thead className="text-muted-foreground"><tr><th className="py-1">Name</th><th>Type</th><th>Compliant</th></tr></thead>
              <tbody>{atts.map((a) => <tr key={a.id} className="border-t border-border"><td className="py-1">{a.name}</td><td>{a.type_name}</td><td className={a.is_compliant ? "text-green-400" : "text-red-400"}>{a.is_compliant ? "yes" : "no"}</td></tr>)}</tbody>
            </table>
          ) : <p className="mt-3 text-sm text-muted-foreground">Run a search.</p>}
        </div>

        {err && <p className="text-sm text-red-400">{err}</p>}
      </div>
    </div>
  );
}
