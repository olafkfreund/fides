"use client";

import { useEffect, useState } from "react";
import { apiGet } from "@/lib/api";

type Assessment = {
  id?: string;
  attestationName?: string;
  modelName?: string;
  assessmentRaw?: string;
  complianceScore?: number;
  createdAt?: string;
};

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

  return (
    <div>
      <h1 className="text-xl font-semibold">AI Audits</h1>
      <p className="mt-1 text-sm text-neutral-500">LLM evaluator reports for reported attestations.</p>

      <div className="mt-6 grid grid-cols-1 gap-5 lg:grid-cols-[320px_1fr]">
        <div className="rounded-xl border border-neutral-800 bg-neutral-900 p-3">
          {list.length ? list.map((a, i) => (
            <button key={a.id ?? i} onClick={() => setSel(a)}
              className={`mb-1 block w-full rounded-md px-3 py-2 text-left text-sm ${sel === a ? "bg-purple-600/15" : "hover:bg-neutral-800"}`}>
              <div className="font-mono">{a.attestationName || "attestation"}</div>
              <div className="text-xs text-neutral-500">{a.modelName} · score {a.complianceScore ?? "—"}</div>
            </button>
          )) : <p className="p-3 text-sm text-neutral-500">No AI assessments yet.</p>}
        </div>
        <div className="rounded-xl border border-neutral-800 bg-neutral-900 p-5">
          {sel ? (
            <>
              <div className="flex items-baseline justify-between">
                <div className="font-mono">{sel.attestationName}</div>
                <div className={`text-lg font-semibold ${(sel.complianceScore ?? 0) >= 80 ? "text-green-400" : "text-amber-400"}`}>{sel.complianceScore ?? "—"}/100</div>
              </div>
              <div className="text-xs text-neutral-500">Model: {sel.modelName}</div>
              <pre className="mt-3 whitespace-pre-wrap break-words rounded-md border border-neutral-800 bg-neutral-950 p-4 text-xs text-neutral-300">{sel.assessmentRaw}</pre>
            </>
          ) : <p className="text-sm text-neutral-500">Select a report.</p>}
        </div>
      </div>
      {err && <p className="mt-4 text-sm text-red-400">{err}</p>}
    </div>
  );
}
