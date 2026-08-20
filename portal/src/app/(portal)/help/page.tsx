"use client";

import { useEffect, useState } from "react";
import Md from "@/components/Md";
import { PageHeader, Panel } from "@/components/dash";

type Doc = { title: string; path: string };

// Docs are the Go-served web/*.md files (root-relative, public). Grouped because
// a flat list of eighteen guides tells you nothing about where to start.
const SECTIONS: { label: string; docs: Doc[] }[] = [
  {
    label: "Start here",
    docs: [
      { title: "First Run — your first hour", path: "/first-run.md" },
      { title: "Getting Started", path: "/getting_started.md" },
      { title: "Installation", path: "/installation.md" },
      { title: "Setup & Seeding", path: "/setup.md" },
    ],
  },
  {
    label: "Onboard your pipelines",
    docs: [
      { title: "Onboarding a Repository", path: "/onboarding-a-repo.md" },
      { title: "CI/CD Gate (GitHub & GitLab)", path: "/ci-gate.md" },
      { title: "Recording Provenance from CI", path: "/ci-provenance.md" },
      { title: "Environment MCP Compliance", path: "/environment-mcp-compliance.md" },
    ],
  },
  {
    label: "Govern & comply",
    docs: [
      { title: "Segregation of Duties", path: "/segregation-of-duties.md" },
      { title: "ServiceNow Integration", path: "/servicenow-integration.md" },
      { title: "ServiceNow Testing", path: "/servicenow-testing.md" },
      { title: "AWS Secrets Manager", path: "/aws-secrets-manager.md" },
    ],
  },
  {
    label: "Reference",
    docs: [
      { title: "Features", path: "/features.md" },
      { title: "CLI Reference", path: "/cli-reference.md" },
      { title: "User Stories", path: "/user-stories.md" },
      { title: "Small & Large Teams", path: "/teams.md" },
      { title: "MCP Server (Claude Code)", path: "/mcp-server.md" },
      { title: "Architecture", path: "/architecture_proposal.md" },
      { title: "Overview (README)", path: "/README.md" },
    ],
  },
];

const ALL = SECTIONS.flatMap((s) => s.docs);

export default function Help() {
  const [sel, setSel] = useState<Doc>(ALL[0]);
  const [q, setQ] = useState("");
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
  const needle = q.trim().toLowerCase();

  const sections = needle
    ? SECTIONS.map((s) => ({
        ...s,
        docs: s.docs.filter((d) => d.title.toLowerCase().includes(needle)),
      })).filter((s) => s.docs.length > 0)
    : SECTIONS;

  return (
    <div>
      <PageHeader
        title="Help & Documentation"
        subtitle="Onboarding, CLI, integrations, and compliance guides."
      />

      <div className="grid grid-cols-1 gap-5 lg:grid-cols-[280px_1fr]">
        <Panel label="Guides">
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Filter guides…"
            className="mb-3 w-full rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground placeholder:text-muted-foreground"
          />
          {sections.map((s) => (
            <div key={s.label} className="mb-4">
              <p className="mb-1 px-3 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                {s.label}
              </p>
              {s.docs.map((d) => (
                <button
                  key={d.path}
                  onClick={() => setSel(d)}
                  className={`mb-1 block w-full rounded-md px-3 py-2 text-left text-sm ${
                    sel.path === d.path
                      ? "bg-primary/15 font-medium text-foreground"
                      : "text-muted-foreground hover:text-foreground"
                  }`}
                >
                  {d.title}
                </button>
              ))}
            </div>
          ))}
          {sections.length === 0 && (
            <p className="px-3 text-sm text-muted-foreground">No guide matches “{q}”.</p>
          )}
        </Panel>
        <Panel>
          {errMsg && (
            <p className="text-sm text-red-400">
              Could not load {sel.path}: {errMsg}
            </p>
          )}
          {!errMsg && !content && <p className="text-sm text-muted-foreground">Loading…</p>}
          {content && <Md>{content}</Md>}
        </Panel>
      </div>
    </div>
  );
}
