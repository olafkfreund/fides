"use client";

import { useEffect, useState } from "react";
import Md from "@/components/Md";

// Docs are the Go-served web/*.md files (root-relative, public).
const DOCS = [
  { title: "Getting Started", path: "/getting_started.md" },
  { title: "Features", path: "/features.md" },
  { title: "CLI Reference", path: "/cli-reference.md" },
  { title: "Environment MCP Compliance", path: "/environment-mcp-compliance.md" },
  { title: "ServiceNow Integration", path: "/servicenow-integration.md" },
  { title: "AWS Secrets Manager", path: "/aws-secrets-manager.md" },
  { title: "Architecture", path: "/architecture_proposal.md" },
  { title: "MCP Server (Claude Code)", path: "/mcp-server.md" },
];

export default function Help() {
  const [sel, setSel] = useState(DOCS[0]);
  const [doc, setDoc] = useState<{ path: string; text: string } | null>(null);
  const [err, setErr] = useState<{ path: string; msg: string } | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetch(sel.path, { credentials: "include" })
      .then((r) => (r.ok ? r.text() : Promise.reject(new Error(`HTTP ${r.status}`))))
      .then((t) => { if (!cancelled) setDoc({ path: sel.path, text: t }); })
      .catch((e) => { if (!cancelled) setErr({ path: sel.path, msg: String(e.message || e) }); });
    return () => { cancelled = true; };
  }, [sel]);

  const content = doc?.path === sel.path ? doc.text : "";
  const errMsg = err?.path === sel.path ? err.msg : "";

  return (
    <div>
      <h1 className="text-xl font-semibold">Help &amp; Documentation</h1>
      <p className="mt-1 text-sm text-muted-foreground">Self-hosting, CLI, integrations, and compliance guides.</p>

      <div className="mt-6 grid grid-cols-1 gap-5 lg:grid-cols-[260px_1fr]">
        <div className="rounded-xl border border-border bg-card p-3">
          {DOCS.map((d) => (
            <button key={d.path} onClick={() => setSel(d)}
              className={`mb-1 block w-full rounded-md px-3 py-2 text-left text-sm ${sel.path === d.path ? "bg-primary/15 font-medium text-foreground" : "text-muted-foreground hover:text-foreground"}`}>
              {d.title}
            </button>
          ))}
        </div>
        <div className="rounded-xl border border-border bg-card p-6">
          {errMsg && <p className="text-sm text-red-400">Could not load {sel.path}: {errMsg}</p>}
          {!errMsg && !content && <p className="text-sm text-muted-foreground">Loading…</p>}
          {content && <Md>{content}</Md>}
        </div>
      </div>
    </div>
  );
}
