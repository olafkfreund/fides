"use client";

import { useEffect, useState } from "react";
import { apiGet } from "@/lib/api";

type MitigatingControl = { code: string; title: string; type: string };
type Risk = {
  key: string;
  title: string;
  description: string;
  attack_vectors?: string[];
  consequences?: string[];
  mitigated_by: MitigatingControl[];
};
type Register = { version: string; risks: Risk[] };

export default function RiskRegister() {
  const [reg, setReg] = useState<Register | null>(null);
  const [err, setErr] = useState("");

  useEffect(() => {
    apiGet<Register>("/api/v1/risk-register")
      .then(setReg)
      .catch((e) => setErr(String((e as Error).message || e)));
  }, []);

  if (err) return <div className="p-6 text-muted-foreground">Failed to load risk register: {err}</div>;
  if (!reg) return <div className="p-6 text-muted-foreground">Loading risk register…</div>;

  const risks = reg.risks ?? [];

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Risk Register</h1>
        <p className="text-muted-foreground text-sm">
          The risks the SDLC controls exist to reduce. Mitigating controls are derived from the
          control catalog. <span className="font-mono">v{reg.version}</span>
        </p>
      </div>

      <div className="grid gap-3 md:grid-cols-2">
        {risks.map((risk) => {
          const covered = risk.mitigated_by.length > 0;
          return (
            <div key={risk.key} className="rounded-lg border border-border bg-card p-4 space-y-2">
              <div className="flex items-center justify-between gap-2">
                <span className="font-medium">{risk.title}</span>
                <span
                  className={`text-xs px-2 py-0.5 rounded-full border border-border ${
                    covered ? "text-primary" : "text-muted-foreground"
                  }`}
                >
                  {covered ? `${risk.mitigated_by.length} control${risk.mitigated_by.length > 1 ? "s" : ""}` : "no control mapped"}
                </span>
              </div>
              <div className="text-xs text-muted-foreground font-mono">{risk.key}</div>
              <p className="text-sm">{risk.description}</p>

              {risk.attack_vectors && risk.attack_vectors.length > 0 && (
                <details className="text-sm">
                  <summary className="cursor-pointer text-muted-foreground">Attack vectors</summary>
                  <ul className="list-disc pl-5 mt-1 space-y-1">
                    {risk.attack_vectors.map((v, i) => (
                      <li key={i}>{v}</li>
                    ))}
                  </ul>
                </details>
              )}

              <div className="flex flex-wrap gap-1 pt-1">
                {risk.mitigated_by.map((c) => (
                  <span
                    key={c.code}
                    title={`${c.code} · ${c.type}`}
                    className="text-xs px-2 py-0.5 rounded bg-muted text-muted-foreground border border-border"
                  >
                    {c.title}
                  </span>
                ))}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
