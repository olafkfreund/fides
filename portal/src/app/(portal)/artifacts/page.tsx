"use client";

import { useEffect, useState } from "react";
import { ChevronRight, Copy, Package, CheckCircle2, XCircle, ShieldCheck, FileText } from "lucide-react";
import { apiGet } from "@/lib/api";

type Artifact = { sha256: string; name: string; type: string; git_commit?: string; created_at?: string };
type Att = { id: string; name: string; type_name: string; is_compliant: boolean; created_at?: string };
type AttDetail = Att & {
  payload?: unknown;
  signed_by?: string;
  signature_algorithm?: string;
  manifestation_reason?: string;
  content_hash?: string;
  artifact_sha256?: string;
};
type SbomItem = { name: string; version?: string; license?: string };

const input = "w-full rounded-md border border-border bg-background px-3 py-2 text-sm font-mono text-foreground";
const panel = "rounded-xl border border-border bg-card p-5";

// Extract a component list from whatever SBOM shape the payload carries
// (CycloneDX .components, SPDX .packages, Syft .artifacts, or a bare array).
function parseSbom(payload: unknown): SbomItem[] {
  if (!payload || typeof payload !== "object") return [];
  const p = payload as Record<string, unknown>;
  let arr: unknown[] = [];
  if (Array.isArray(payload)) arr = payload as unknown[];
  else if (Array.isArray(p.components)) arr = p.components as unknown[];
  else if (Array.isArray(p.packages)) arr = p.packages as unknown[];
  else if (Array.isArray(p.artifacts)) arr = p.artifacts as unknown[];
  else return [];
  return arr.map((raw) => {
    const c = (raw || {}) as Record<string, unknown>;
    const licenses = c.licenses;
    let license: string | undefined;
    if (Array.isArray(licenses)) {
      license = licenses.map((l) => {
        const lo = l as Record<string, unknown>;
        const inner = lo.license as Record<string, unknown> | undefined;
        return (inner?.id || inner?.name || lo.expression) as string | undefined;
      }).filter(Boolean).join(", ") || undefined;
    } else if (typeof c.license === "string") license = c.license;
    return {
      name: String(c.name || c.packageName || "—"),
      version: (c.version || c.versionInfo) as string | undefined,
      license,
    };
  });
}

function EvidenceBlock({ att }: { att: AttDetail }) {
  const json = att.payload != null ? JSON.stringify(att.payload, null, 2) : "";
  return (
    <div className="mt-2 space-y-2">
      {(att.signed_by || att.content_hash) && (
        <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground">
          {att.signed_by && <span>signed by <span className="text-foreground">{att.signed_by}</span>{att.signature_algorithm ? ` (${att.signature_algorithm})` : ""}</span>}
          {att.content_hash && <span>chain hash <code className="font-mono">{att.content_hash.slice(0, 16)}…</code></span>}
        </div>
      )}
      {json && <pre className="max-h-72 overflow-auto rounded-md border border-border bg-background p-3 font-mono text-xs leading-relaxed text-foreground/90">{json}</pre>}
    </div>
  );
}

export default function Artifacts() {
  const [sha, setSha] = useState("");
  const [name, setName] = useState("");
  const [arts, setArts] = useState<Artifact[]>([]);
  const [openSha, setOpenSha] = useState("");
  const [atts, setAtts] = useState<Att[]>([]);
  const [sbom, setSbom] = useState<{ items: SbomItem[]; status: string; raw?: unknown } | null>(null);
  const [openAtt, setOpenAtt] = useState<Record<string, AttDetail>>({});
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");

  const searchArts = () => {
    const q = new URLSearchParams();
    if (sha) q.set("sha", sha);
    if (name) q.set("name", name);
    apiGet<Artifact[]>(`/api/v1/search/artifacts?${q}`).then((a) => setArts(a || [])).catch((e) => setErr(String(e.message || e)));
  };
  useEffect(() => { searchArts(); }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const openArtifact = async (a: Artifact) => {
    if (openSha === a.sha256) { setOpenSha(""); return; }
    setOpenSha(a.sha256); setAtts([]); setSbom(null); setOpenAtt({}); setLoading(true); setErr("");
    try {
      const list = await apiGet<Att[]>(`/api/v1/search/attestations?sha=${encodeURIComponent(a.sha256)}`);
      setAtts(list || []);
      const sbomAtt = (list || []).find((x) => /sbom/i.test(x.type_name) || /sbom/i.test(x.name));
      if (sbomAtt) {
        const d = await apiGet<AttDetail>(`/api/v1/attestations/${sbomAtt.id}`);
        const items = parseSbom(d.payload);
        setSbom({ items, status: sbomAtt.is_compliant ? "compliant" : "non-compliant", raw: items.length ? undefined : d.payload });
      }
    } catch (e) { setErr(String((e as Error).message)); }
    finally { setLoading(false); }
  };

  const toggleAtt = async (id: string) => {
    if (openAtt[id]) { setOpenAtt((s) => { const n = { ...s }; delete n[id]; return n; }); return; }
    try { const d = await apiGet<AttDetail>(`/api/v1/attestations/${id}`); setOpenAtt((s) => ({ ...s, [id]: d })); }
    catch (e) { setErr(String((e as Error).message)); }
  };

  return (
    <div>
      <h1 className="text-xl font-semibold">Artifacts &amp; SBOM</h1>
      <p className="mt-1 text-sm text-muted-foreground">Search build artifacts; click one for its attestations and SBOM.</p>

      <div className={`${panel} mt-6`}>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-[1fr_1fr_auto]">
          <input className={input} value={sha} onChange={(e) => setSha(e.target.value)} placeholder="SHA256 prefix" />
          <input className={input} value={name} onChange={(e) => setName(e.target.value)} placeholder="name" />
          <button onClick={searchArts} className="rounded-md bg-primary px-6 py-2 text-sm font-semibold text-primary-foreground">Search</button>
        </div>

        {arts.length ? (
          <div className="mt-4 flex flex-col divide-y divide-border">
            {arts.map((a) => {
              const isOpen = openSha === a.sha256;
              return (
                <div key={a.sha256} className="py-3 first:pt-0">
                  <button onClick={() => openArtifact(a)} aria-expanded={isOpen} className="flex w-full items-start gap-3 text-left">
                    <ChevronRight className={`mt-0.5 size-4 shrink-0 text-muted-foreground transition-transform ${isOpen ? "rotate-90" : ""}`} />
                    <span className="min-w-0 flex-1">
                      <span className="flex flex-wrap items-center justify-between gap-2">
                        <span className="text-sm font-medium">{a.name} <span className="text-xs text-muted-foreground">· {a.type}</span></span>
                        <span className="font-mono text-xs text-muted-foreground">{a.git_commit ? `commit ${a.git_commit.slice(0, 12)}` : ""}</span>
                      </span>
                      <span className="mt-1 block truncate font-mono text-xs text-muted-foreground">sha256 {a.sha256}</span>
                    </span>
                  </button>

                  {isOpen && (
                    <div className="mt-3 space-y-4 pl-7">
                      <div className="flex flex-wrap items-center gap-2 text-xs">
                        <button onClick={() => navigator.clipboard?.writeText(a.sha256)} className="flex items-center gap-1 rounded border border-border px-2 py-0.5 text-muted-foreground hover:text-foreground"><Copy className="size-3" /> Copy SHA256</button>
                        {a.created_at && <span className="text-muted-foreground">recorded {a.created_at.replace("T", " ").slice(0, 19)}</span>}
                      </div>

                      {loading ? <p className="text-sm text-muted-foreground">Loading…</p> : (
                        <>
                          {/* SBOM */}
                          <div>
                            <div className="mb-1.5 flex items-center gap-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground"><Package className="size-3.5" /> SBOM {sbom ? <span className={sbom.status === "compliant" ? "text-green-400" : "text-red-400"}>· {sbom.status}</span> : null}</div>
                            {sbom ? (
                              sbom.items.length ? (
                                <div className="overflow-hidden rounded-md border border-border">
                                  <div className="max-h-72 overflow-auto">
                                    <table className="w-full text-left text-xs">
                                      <thead className="sticky top-0 bg-muted/60 text-muted-foreground"><tr><th className="px-3 py-1.5 font-medium">Component</th><th className="px-3 py-1.5 font-medium">Version</th><th className="px-3 py-1.5 font-medium">License</th></tr></thead>
                                      <tbody>
                                        {sbom.items.map((c, i) => (
                                          <tr key={i} className="border-t border-border"><td className="px-3 py-1.5 font-mono">{c.name}</td><td className="px-3 py-1.5 font-mono text-muted-foreground">{c.version || "—"}</td><td className="px-3 py-1.5 text-muted-foreground">{c.license || "—"}</td></tr>
                                        ))}
                                      </tbody>
                                    </table>
                                  </div>
                                  <div className="border-t border-border bg-background px-3 py-1.5 text-xs text-muted-foreground">{sbom.items.length} components</div>
                                </div>
                              ) : (
                                <div className="rounded-md border border-border bg-background p-3 text-xs text-muted-foreground">
                                  SBOM attestation present but no recognizable component list. Raw payload:
                                  <pre className="mt-1 max-h-48 overflow-auto font-mono text-foreground/80">{JSON.stringify(sbom.raw, null, 2)}</pre>
                                </div>
                              )
                            ) : <p className="text-xs text-muted-foreground">No SBOM attestation recorded for this artifact.</p>}
                          </div>

                          {/* Attestations */}
                          <div>
                            <div className="mb-1.5 flex items-center gap-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground"><ShieldCheck className="size-3.5" /> Attestations ({atts.length})</div>
                            {atts.length ? (
                              <div className="flex flex-col divide-y divide-border rounded-md border border-border">
                                {atts.map((at) => (
                                  <div key={at.id} className="px-3 py-2">
                                    <button onClick={() => toggleAtt(at.id)} className="flex w-full items-center gap-2 text-left text-sm">
                                      {at.is_compliant ? <CheckCircle2 className="size-3.5 shrink-0 text-green-400" /> : <XCircle className="size-3.5 shrink-0 text-red-400" />}
                                      <span className="min-w-0 flex-1 truncate">{at.name} <span className="text-xs text-muted-foreground">· {at.type_name}</span></span>
                                      <FileText className="size-3.5 shrink-0 text-muted-foreground" />
                                    </button>
                                    {openAtt[at.id] && <EvidenceBlock att={openAtt[at.id]} />}
                                  </div>
                                ))}
                              </div>
                            ) : <p className="text-xs text-muted-foreground">No attestations recorded for this artifact.</p>}
                          </div>
                        </>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        ) : <p className="mt-3 text-sm text-muted-foreground">No results.</p>}
      </div>

      {err && <p className="mt-4 text-sm text-red-400">{err}</p>}
    </div>
  );
}
