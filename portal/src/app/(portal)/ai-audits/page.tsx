"use client";

import { useEffect, useState } from "react";
import { Bot } from "lucide-react";
import { apiGet } from "@/lib/api";
import { PageHeader, Panel, Chip } from "@/components/dash";

type Assessment = {
  id?: string;
  attestationName?: string;
  modelName?: string;
  assessmentRaw?: string;
  complianceScore?: number;
  createdAt?: string;
};

function scoreColor(s?: number) {
  if (s == null) return "text-muted-foreground";
  return s >= 80 ? "text-green-400" : s >= 50 ? "text-amber-400" : "text-red-400";
}
function scoreBar(s?: number) {
  if (s == null) return "bg-muted-foreground";
  return s >= 80 ? "bg-green-500" : s >= 50 ? "bg-amber-500" : "bg-red-500";
}

// Parse the LLM's free-text assessment into labelled sections + a score. Lines like
// "Compliance Status: …" become a titled block; "COMPLIANCE_SCORE: 100" is lifted out.
function parseAssessment(raw: string): { score?: number; sections: { label: string; body: string }[] } {
  const sections: { label: string; body: string }[] = [];
  let score: number | undefined;
  let current: { label: string; body: string } | null = null;
  const labelRe = /^([A-Z][A-Za-z0-9 /&_-]{1,40}):\s*(.*)$/;
  for (const line of raw.split(/\r?\n/)) {
    const t = line.trim();
    if (!t) continue;
    const m = t.match(labelRe);
    if (m) {
      const label = m[1].trim();
      const rest = m[2].trim();
      if (/^COMPLIANCE[_ ]SCORE$/i.test(label)) {
        const n = parseInt(rest, 10);
        if (!isNaN(n)) score = n;
        current = null;
        continue;
      }
      current = { label, body: rest };
      sections.push(current);
    } else if (current) {
      current.body += (current.body ? " " : "") + t;
    } else {
      current = { label: "", body: t };
      sections.push(current);
    }
  }
  return { score, sections };
}

export default function AIAudits() {
  const [list, setList] = useState<Assessment[]>([]);
  const [sel, setSel] = useState<Assessment | null>(null);
  const [err, setErr] = useState("");

  useEffect(() => {
    apiGet<Assessment[]>("/api/v1/ai-assessments").then((a) => {
      setList(a || []);
      if (a && a.length) setSel(a[0]);
    }).catch((e) => setErr(String(e.message || e)));
  }, []);

  const parsed = sel ? parseAssessment(sel.assessmentRaw || "") : null;
  const score = parsed?.score ?? sel?.complianceScore;
  const complianceSection = parsed?.sections.find((s) => /compliance status/i.test(s.label));
  const compliant = complianceSection ? /(?<!non-?)\bcompliant/i.test(complianceSection.body) : undefined;

  return (
    <div>
      <PageHeader title="AI Audits" subtitle="LLM evaluator reports for reported attestations." />

      <div className="grid grid-cols-1 gap-5 lg:grid-cols-[300px_1fr]">
        {/* Report list */}
        <div className="max-h-[76vh] overflow-y-auto rounded-xl border border-border bg-card p-2">
          {list.length ? list.map((a, i) => (
            <button key={a.id ?? i} onClick={() => setSel(a)}
              className={`mb-1 flex w-full items-center gap-2 rounded-md px-3 py-2 text-left text-sm ${sel === a ? "bg-primary/15" : "hover:bg-accent"}`}>
              <span className="min-w-0 flex-1">
                <span className="block truncate font-mono">{a.attestationName || "attestation"}</span>
                <span className="block text-xs text-muted-foreground">{a.modelName}</span>
              </span>
              <span className={`shrink-0 font-mono tabular-nums text-xs font-semibold ${scoreColor(a.complianceScore)}`}>{a.complianceScore ?? "—"}</span>
            </button>
          )) : <p className="p-3 text-sm text-muted-foreground">No AI assessments yet.</p>}
        </div>

        {/* Detail */}
        <Panel>
          {sel && parsed ? (
            <>
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="flex items-center gap-2 font-mono text-base font-semibold"><Bot className="size-4 text-primary" />{sel.attestationName}</div>
                  <div className="mt-0.5 text-xs text-muted-foreground">Model: {sel.modelName}{sel.createdAt ? ` · ${sel.createdAt.replace("T", " ").slice(0, 19)}` : ""}</div>
                </div>
                <div className="text-right">
                  <div className={`font-mono tabular-nums text-2xl font-bold ${scoreColor(score)}`}>{score ?? "—"}<span className="text-sm font-normal text-muted-foreground">/100</span></div>
                  {compliant !== undefined && (
                    <div className="mt-1">
                      <Chip tone={compliant ? "ok" : "bad"}>{compliant ? "Compliant" : "Non-compliant"}</Chip>
                    </div>
                  )}
                </div>
              </div>

              {/* Score bar */}
              {score != null && (
                <div className="mt-3 h-1.5 w-full rounded-full bg-muted"><div className={`h-1.5 rounded-full ${scoreBar(score)}`} style={{ width: `${Math.max(2, Math.min(100, score))}%` }} /></div>
              )}

              {/* Parsed sections */}
              <div className="mt-4 flex flex-col gap-3">
                {parsed.sections.map((s, i) => (
                  <div key={i} className="rounded-md border border-border bg-background p-3">
                    {s.label && <div className="mb-1 text-xs font-semibold uppercase tracking-wide text-primary">{s.label}</div>}
                    <p className="text-sm leading-relaxed text-foreground/90">{s.body}</p>
                  </div>
                ))}
                {!parsed.sections.length && <p className="text-sm text-muted-foreground whitespace-pre-wrap">{sel.assessmentRaw}</p>}
              </div>
            </>
          ) : <p className="text-sm text-muted-foreground">Select a report.</p>}
        </Panel>
      </div>
      {err && <p className="mt-4 text-sm text-red-400">{err}</p>}
    </div>
  );
}
