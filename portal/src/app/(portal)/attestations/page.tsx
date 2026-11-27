"use client";

import { useEffect, useState } from "react";
import { CheckCircle2, XCircle, ChevronRight } from "lucide-react";
import { apiGet } from "@/lib/api";
import { usePagedList } from "@/lib/usePagedList";
import { LoadMore } from "@/components/LoadMore";
import { PageHeader, Panel, StatTile, Chip, Donut, DistBars } from "@/components/dash";

type Att = { id: string; name: string; type_name: string; is_compliant: boolean; trail_id: string; created_at?: string };
type ValidationError = { code: string; path?: string; message: string };
type AttDetail = Att & { payload?: unknown; signed_by?: string; signature_algorithm?: string; content_hash?: string; artifact_sha256?: string; validation_errors?: ValidationError[] | null };
type AttestationType = { id: string; name: string; description?: string; schema?: string | null };

const control = "rounded-md border border-border bg-background px-3 py-2 text-sm";

export default function Attestations() {
  const ledger = usePagedList<Att>();
  const definitions = usePagedList<AttestationType>();
  const atts = ledger.items;
  const [type, setType] = useState("");
  const [compliance, setCompliance] = useState("");
  const [name, setName] = useState("");
  const [open, setOpen] = useState<Record<string, AttDetail>>({});
  const [err, setErr] = useState("");

  const toggle = async (id: string) => {
    if (open[id]) { setOpen((s) => { const n = { ...s }; delete n[id]; return n; }); return; }
    try { const d = await apiGet<AttDetail>(`/api/v1/attestations/${id}`); setOpen((s) => ({ ...s, [id]: d })); }
    catch (e) { setErr(String((e as Error).message)); }
  };

  const load = (over?: { type?: string; compliance?: string }) => {
    const t = over?.type ?? type;
    const c = over?.compliance ?? compliance;
    const q = new URLSearchParams();
    if (t) q.set("type", t);
    if (c) q.set("compliant", c);
    if (name) q.set("name", name);
    ledger.load(`/api/v1/search/attestations?${q}`);
  };
  // Preset filters from the URL so dashboard deep-links (e.g. ?compliant=false for
  // "Active Alerts") land pre-filtered. Static export → read window.location directly.
  useEffect(() => {
    const sp = new URLSearchParams(window.location.search);
    const c = sp.get("compliant") || "";
    const t = sp.get("type") || "";
    // eslint-disable-next-line react-hooks/set-state-in-effect
    if (c) setCompliance(c);
    if (t) setType(t);
    const timer = setTimeout(() => {
      load({ compliance: c, type: t });
      definitions.load("/api/v1/attestation-types");
    }, 0);
    return () => clearTimeout(timer);
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const shown = atts.filter((a) => a.name.toLowerCase().includes(name.toLowerCase()));
  const compliant = atts.filter((a) => a.is_compliant).length;
  const types = [...new Set(atts.map((a) => a.type_name))];
  const byType = atts.reduce<Record<string, number>>((acc, a) => { acc[a.type_name] = (acc[a.type_name] || 0) + 1; return acc; }, {});

  return (
    <div>
      <PageHeader title="Attestations" subtitle="Evidence recorded against build trails." />

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <StatTile label="Loaded attestations" value={String(atts.length)} />
        <StatTile label="Compliant" value={`${atts.length ? Math.round((compliant / atts.length) * 100) : 0}%`} sub={`${compliant} of ${atts.length}`} color="text-green-400" />
        <StatTile label="Evidence Types" value={String(types.length)} />
      </div>

      {atts.length > 0 && (
        <Panel label="Compliance" className="mt-4">
          <div className="flex flex-wrap items-center gap-x-10 gap-y-6">
            <Donut value={atts.length ? compliant / atts.length : 0} color="#35C08A" sublabel="compliant" />
            <div className="min-w-[280px] flex-1">
              <div className="mb-3 text-[11px] uppercase tracking-[0.16em] text-muted-foreground">By evidence type</div>
              <DistBars items={Object.entries(byType).map(([label, value]) => ({ label, value }))} />
            </div>
          </div>
        </Panel>
      )}

      <Panel label="Ledger" className="mt-6">
        <div className="mb-4 flex flex-wrap items-center gap-3">
          <input className={`${control} w-56`} value={name} onChange={(e) => setName(e.target.value)} placeholder="Find by name…" />
          <input className={`${control} w-48`} value={type} onChange={(e) => setType(e.target.value)} placeholder="Type (junit, snyk…)" />
          <select className={control} value={compliance} onChange={(e) => setCompliance(e.target.value)}>
            <option value="">Any compliance</option><option value="true">Compliant</option><option value="false">Non-compliant</option>
          </select>
          <button onClick={() => load()} className="rounded-md bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground">Apply</button>
        </div>

        {ledger.loading && !atts.length ? <p className="text-sm text-muted-foreground">Loading…</p> : shown.length ? (
          <div className="flex flex-col divide-y divide-border">
            {shown.map((a) => {
              const d = open[a.id];
              return (
                <div key={a.id} className="py-2.5">
                  <button onClick={() => toggle(a.id)} aria-expanded={!!d} className="flex w-full items-center gap-3 text-left">
                    <ChevronRight className={`size-4 shrink-0 text-muted-foreground transition-transform ${d ? "rotate-90" : ""}`} />
                    {a.is_compliant ? <CheckCircle2 className="size-4 shrink-0 text-green-400" /> : <XCircle className="size-4 shrink-0 text-red-400" />}
                    <div className="min-w-0 flex-1">
                      <div className="truncate text-sm font-medium">{a.name}</div>
                      <div className="truncate font-mono text-xs text-muted-foreground">trail {a.trail_id.slice(0, 8)} · {(a.created_at || "").replace("T", " ").slice(0, 19)}</div>
                    </div>
                    <Chip tone="muted">{a.type_name}</Chip>
                    <span className="w-24 text-right"><Chip tone={a.is_compliant ? "ok" : "bad"}>{a.is_compliant ? "pass" : "fail"}</Chip></span>
                  </button>
                  {d && (
                    <div className="mt-2 space-y-2 pl-11">
                      {(d.signed_by || d.content_hash || d.artifact_sha256) && (
                        <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground">
                          {d.artifact_sha256 && <span>artifact <code className="font-mono">{d.artifact_sha256.slice(0, 16)}…</code></span>}
                          {d.signed_by && <span>signed by <span className="text-foreground">{d.signed_by}</span>{d.signature_algorithm ? ` (${d.signature_algorithm})` : ""}</span>}
                          {d.content_hash && <span>chain hash <code className="font-mono">{d.content_hash.slice(0, 16)}…</code></span>}
                        </div>
                      )}
                      {!!d.validation_errors?.length && (
                        <div className="rounded-md border border-border p-3 text-sm">
                          <p className="font-medium text-red-400">Validation failures</p>
                          <ul className="mt-1 list-disc space-y-1 pl-5">
                            {d.validation_errors.map(({ code, path, message }, index) => (
                              <li key={index} className="break-words">
                                {message} <code className="text-xs text-muted-foreground">({code})</code>
                                {path && <> at <code className="text-xs">{path}</code></>}
                              </li>
                            ))}
                          </ul>
                        </div>
                      )}
                      <pre className="max-h-72 overflow-auto rounded-md border border-border bg-background p-3 font-mono text-xs leading-relaxed text-foreground/90">{d.payload != null ? JSON.stringify(d.payload, null, 2) : "(no payload)"}</pre>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        ) : <p className="text-sm text-muted-foreground">No attestations match.</p>}
        <LoadMore {...ledger} />
        {ledger.error && <p role="alert" className="mt-3 text-sm text-red-400">{ledger.error}</p>}
      </Panel>

      <Panel label="Attestation Types" className="mt-6">
        <div className="divide-y divide-border">
          {definitions.items.map((definition) => (
            <details key={definition.id} className="py-2 text-sm">
              <summary className="cursor-pointer font-medium">{definition.name}</summary>
              {definition.description && <p className="my-2 text-muted-foreground">{definition.description}</p>}
              {definition.schema ? (
                <pre aria-label="JSON Schema" className="mt-2 max-h-72 overflow-auto whitespace-pre-wrap break-all rounded-md border border-border bg-background p-3 font-mono text-xs">
                  {definition.schema}
                </pre>
              ) : <p className="mt-2 text-muted-foreground">No JSON Schema configured.</p>}
            </details>
          ))}
        </div>
        {!definitions.items.length && !definitions.error && (
          <p className="text-sm text-muted-foreground">{definitions.loading ? "Loading…" : "No attestation types configured."}</p>
        )}
        <LoadMore {...definitions} />
        {definitions.error && <p role="alert" className="mt-3 text-sm text-red-400">{definitions.error}</p>}
      </Panel>

      {err && <p className="mt-4 text-sm text-red-400">{err}</p>}
    </div>
  );
}
