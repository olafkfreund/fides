"use client";

import { useEffect, useState } from "react";
import { apiGet } from "@/lib/api";

type Policy = { id: string; name: string; description?: string; rules?: string };

export default function Policies() {
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [sel, setSel] = useState<Policy | null>(null);
  const [err, setErr] = useState("");

  useEffect(() => {
    apiGet<Policy[]>("/api/v1/policies").then((p) => {
      setPolicies(p || []);
      if (p && p.length) setSel(p[0]);
    }).catch((e) => setErr(String(e.message || e)));
  }, []);

  return (
    <div>
      <h1 className="text-xl font-semibold">Policies</h1>
      <p className="mt-1 text-sm text-muted-foreground">Deterministic jq policy gates.</p>

      <div className="mt-6 grid grid-cols-1 gap-5 lg:grid-cols-[280px_1fr]">
        <div className="rounded-xl border border-border bg-card p-3">
          {policies.length ? policies.map((p) => (
            <button key={p.id} onClick={() => setSel(p)}
              className={`mb-1 block w-full rounded-md px-3 py-2 text-left text-sm ${sel?.id === p.id ? "bg-primary/15" : "hover:bg-accent"}`}>
              <div className="font-mono">{p.name}</div>
              {p.description && <div className="text-xs text-muted-foreground">{p.description}</div>}
            </button>
          )) : <p className="p-3 text-sm text-muted-foreground">No policies.</p>}
        </div>
        <div className="rounded-xl border border-border bg-card p-5">
          {sel ? (
            <>
              <div className="font-mono">{sel.name}</div>
              {sel.description && <div className="text-xs text-muted-foreground">{sel.description}</div>}
              <pre className="mt-3 overflow-auto rounded-md border border-border bg-background p-4 text-xs text-green-400">{sel.rules || "(no rules)"}</pre>
            </>
          ) : <p className="text-sm text-muted-foreground">Select a policy.</p>}
        </div>
      </div>
      {err && <p className="mt-4 text-sm text-red-400">{err}</p>}
    </div>
  );
}
