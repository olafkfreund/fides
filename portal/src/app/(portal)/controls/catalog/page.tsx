"use client";

import { useEffect, useState } from "react";
import { apiGet } from "@/lib/api";

type FrameworkRef = { framework: string; clause: string; note: string };
type CatalogControl = {
  code: string;
  title: string;
  type: string;
  area: string;
  summary: string;
  requirements: string[];
  mitigates?: string[];
  fides_evidence?: string[];
  framework_refs: FrameworkRef[];
};
type Catalog = { version: string; controls: CatalogControl[] };

const AREAS = ["build", "release", "runtime", "change", "lifecycle"];

export default function ControlCatalog() {
  const [cat, setCat] = useState<Catalog | null>(null);
  const [err, setErr] = useState("");

  useEffect(() => {
    apiGet<Catalog>("/api/v1/control-catalog")
      .then(setCat)
      .catch((e) => setErr(String((e as Error).message || e)));
  }, []);

  if (err) return <div className="p-6 text-muted-foreground">Failed to load catalog: {err}</div>;
  if (!cat) return <div className="p-6 text-muted-foreground">Loading catalog…</div>;

  const controls = cat.controls ?? [];

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Control Catalog</h1>
        <p className="text-muted-foreground text-sm">
          Fides SDLC controls — requirements, risks mitigated, and framework mappings.{" "}
          <span className="font-mono">v{cat.version}</span>
        </p>
      </div>

      {AREAS.filter((a) => controls.some((c) => c.area === a)).map((area) => (
        <section key={area} className="space-y-3">
          <h2 className="text-lg font-medium capitalize border-b border-border pb-1">{area}</h2>
          <div className="grid gap-3 md:grid-cols-2">
            {controls
              .filter((c) => c.area === area)
              .map((c) => (
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

                  <details className="text-sm">
                    <summary className="cursor-pointer text-muted-foreground">
                      Requirements ({c.requirements.length})
                    </summary>
                    <ul className="list-disc pl-5 mt-1 space-y-1">
                      {c.requirements.map((r, i) => (
                        <li key={i}>{r}</li>
                      ))}
                    </ul>
                  </details>

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
