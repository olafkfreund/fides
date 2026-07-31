"use client";

import { useEffect, useState } from "react";
import { apiGet } from "@/lib/api";

type FrameworkRef = { framework: string; clause: string; note: string };
type Control = {
  code: string;
  title: string;
  type: string;
  summary: string;
  requirements: string[];
  framework_refs: FrameworkRef[];
};
type Phase = {
  name: string;
  blurb: string;
  preventive: number;
  detective: number;
  controls: Control[];
};
type SDLC = { version: string; phases: Phase[] };

export default function SecureSDLC() {
  const [sdlc, setSdlc] = useState<SDLC | null>(null);
  const [err, setErr] = useState("");
  const [downloading, setDownloading] = useState(false);

  useEffect(() => {
    apiGet<SDLC>("/api/v1/sdlc")
      .then(setSdlc)
      .catch((e) => setErr(String((e as Error).message || e)));
  }, []);

  const downloadAuditPack = async () => {
    setDownloading(true);
    try {
      const pack = await apiGet<unknown>("/api/v1/audit-pack");
      const blob = new Blob([JSON.stringify(pack, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `fides-audit-pack-${new Date().toISOString().slice(0, 10)}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      setErr(String((e as Error).message || e));
    } finally {
      setDownloading(false);
    }
  };

  if (err) return <div className="p-6 text-muted-foreground">Failed to load: {err}</div>;
  if (!sdlc) return <div className="p-6 text-muted-foreground">Loading…</div>;

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold">Secure SDLC</h1>
          <p className="text-muted-foreground text-sm">
            Our secure software lifecycle — Build, Process, Runtime — generated from the control catalog.
            Each control is enforced/evidenced by Fides. <span className="font-mono">v{sdlc.version}</span>
          </p>
        </div>
        <button
          onClick={downloadAuditPack}
          disabled={downloading}
          className="shrink-0 rounded bg-primary/15 text-primary border border-border px-3 py-1.5 text-sm disabled:opacity-50"
        >
          {downloading ? "Preparing…" : "Download audit pack"}
        </button>
      </div>

      {sdlc.phases.map((phase) => (
        <section key={phase.name} className="space-y-3">
          <div className="border-b border-border pb-1">
            <h2 className="text-lg font-medium">{phase.name}</h2>
            <p className="text-sm text-muted-foreground">
              {phase.blurb}{" "}
              <span className="text-xs">
                · {phase.controls.length} controls ({phase.preventive} preventive, {phase.detective} detective)
              </span>
            </p>
          </div>
          <div className="grid gap-3 md:grid-cols-2">
            {phase.controls.map((c) => (
              <div key={c.code} className="rounded-lg border border-border bg-card p-4 space-y-2">
                <div className="flex items-center justify-between gap-2">
                  <span className="font-medium">{c.title}</span>
                  <span
                    className={`text-xs px-2 py-0.5 rounded-full border border-border ${
                      c.type === "preventive" ? "text-primary" : "text-muted-foreground"
                    }`}
                  >
                    {c.type}
                  </span>
                </div>
                <div className="text-xs text-muted-foreground font-mono">{c.code}</div>
                <p className="text-sm">{c.summary}</p>
                <div className="flex flex-wrap gap-1 pt-1">
                  {c.framework_refs.map((ref, i) => (
                    <span
                      key={i}
                      title={ref.note}
                      className="text-xs px-2 py-0.5 rounded bg-muted text-muted-foreground border border-border"
                    >
                      {ref.framework} {ref.clause}
                    </span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </section>
      ))}
    </div>
  );
}
