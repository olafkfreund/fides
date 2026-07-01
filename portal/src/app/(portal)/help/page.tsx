"use client";

import { useEffect, useState } from "react";
import Markdown from "react-markdown";
import remarkGfm from "remark-gfm";

// Docs are the Go-served web/*.md files (root-relative, public).
const DOCS = [
  { title: "Getting Started", path: "/getting_started.md" },
  { title: "Features", path: "/features.md" },
  { title: "CLI Reference", path: "/cli-reference.md" },
  { title: "Environment MCP Compliance", path: "/environment-mcp-compliance.md" },
  { title: "ServiceNow Integration", path: "/servicenow-integration.md" },
  { title: "AWS Secrets Manager", path: "/aws-secrets-manager.md" },
  { title: "Architecture", path: "/architecture_proposal.md" },
];

type C<T extends keyof React.JSX.IntrinsicElements> = React.ComponentPropsWithoutRef<T>;
const mdComponents = {
  h1: (p: C<"h1">) => <h1 className="mt-6 mb-3 text-2xl font-bold text-foreground" {...p} />,
  h2: (p: C<"h2">) => <h2 className="mt-6 mb-2 text-xl font-semibold text-foreground" {...p} />,
  h3: (p: C<"h3">) => <h3 className="mt-4 mb-2 text-lg font-semibold text-foreground" {...p} />,
  p: (p: C<"p">) => <p className="my-3 leading-relaxed text-muted-foreground" {...p} />,
  ul: (p: C<"ul">) => <ul className="my-3 list-disc pl-6 text-muted-foreground" {...p} />,
  ol: (p: C<"ol">) => <ol className="my-3 list-decimal pl-6 text-muted-foreground" {...p} />,
  li: (p: C<"li">) => <li className="my-1" {...p} />,
  a: (p: C<"a">) => <a className="text-primary underline" {...p} />,
  code: (p: C<"code">) => <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs text-foreground" {...p} />,
  pre: (p: C<"pre">) => <pre className="my-3 overflow-auto rounded-md border border-border bg-background p-4 text-xs" {...p} />,
  table: (p: C<"table">) => <table className="my-3 w-full text-left text-sm" {...p} />,
  th: (p: C<"th">) => <th className="border-b border-border py-1 pr-4 text-muted-foreground" {...p} />,
  td: (p: C<"td">) => <td className="border-b border-border py-1 pr-4" {...p} />,
};

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
          {content && <Markdown remarkPlugins={[remarkGfm]} components={mdComponents}>{content}</Markdown>}
        </div>
      </div>
    </div>
  );
}
