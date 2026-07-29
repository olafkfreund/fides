"use client";

import { useEffect, useState } from "react";
import Md from "@/components/Md";
import { PageHeader, Panel } from "@/components/dash";

// Docs are the Go-served web/*.md files (root-relative, public).
const DOCS = [
  { title: "Getting Started", path: "/getting_started.md" },
  { title: "Small & Large Teams", path: "/teams.md" },
  { title: "User Stories", path: "/user-stories.md" },
  { title: "CI/CD Gate (GitHub & GitLab)", path: "/ci-gate.md" },
  { title: "Setup & Seeding", path: "/setup.md" },
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
      <PageHeader title="Help & Documentation" subtitle="Self-hosting, CLI, integrations, and compliance guides." />

      <div className="grid grid-cols-1 gap-5 lg:grid-cols-[260px_1fr]">
        <Panel label="Guides">
          {DOCS.map((d) => (
            <button key={d.path} onClick={() => setSel(d)}
              className={`mb-1 block w-full rounded-md px-3 py-2 text-left text-sm ${sel.path === d.path ? "bg-primary/15 font-medium text-foreground" : "text-muted-foreground hover:text-foreground"}`}>
              {d.title}
            </button>
          ))}
        </Panel>
        <Panel>
          {errMsg && <p className="text-sm text-red-400">Could not load {sel.path}: {errMsg}</p>}
          {!errMsg && !content && <p className="text-sm text-muted-foreground">Loading…</p>}
          {content && <Md>{content}</Md>}
        </Panel>
      </div>
    </div>
  );
}
