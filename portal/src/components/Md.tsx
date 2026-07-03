"use client";

import Markdown from "react-markdown";
import remarkGfm from "remark-gfm";

type C<T extends keyof React.JSX.IntrinsicElements> = React.ComponentPropsWithoutRef<T>;

// Shared styled markdown renderer (used by AI Audits and Help & Docs) so LLM
// reports and docs render as readable formatted text, not raw markdown.
const components = {
  h1: (p: C<"h1">) => <h1 className="mt-6 mb-3 text-2xl font-bold text-foreground" {...p} />,
  h2: (p: C<"h2">) => <h2 className="mt-6 mb-2 text-xl font-semibold text-foreground" {...p} />,
  h3: (p: C<"h3">) => <h3 className="mt-4 mb-2 text-lg font-semibold text-foreground" {...p} />,
  h4: (p: C<"h4">) => <h4 className="mt-3 mb-1 font-semibold text-foreground" {...p} />,
  p: (p: C<"p">) => <p className="my-3 leading-relaxed text-foreground/90" {...p} />,
  ul: (p: C<"ul">) => <ul className="my-3 list-disc pl-6 text-foreground/90" {...p} />,
  ol: (p: C<"ol">) => <ol className="my-3 list-decimal pl-6 text-foreground/90" {...p} />,
  li: (p: C<"li">) => <li className="my-1" {...p} />,
  a: (p: C<"a">) => <a className="text-primary underline" {...p} />,
  strong: (p: C<"strong">) => <strong className="font-semibold text-foreground" {...p} />,
  blockquote: (p: C<"blockquote">) => <blockquote className="my-3 border-l-2 border-primary/50 pl-4 text-muted-foreground" {...p} />,
  hr: (p: C<"hr">) => <hr className="my-4 border-border" {...p} />,
  code: (p: C<"code">) => <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs text-foreground" {...p} />,
  pre: (p: C<"pre">) => <pre className="my-3 overflow-auto rounded-md border border-border bg-background p-4 text-xs" {...p} />,
  table: (p: C<"table">) => <table className="my-3 w-full text-left text-sm" {...p} />,
  th: (p: C<"th">) => <th className="border-b border-border py-1 pr-4 text-muted-foreground" {...p} />,
  td: (p: C<"td">) => <td className="border-b border-border py-1 pr-4" {...p} />,
};

export default function Md({ children }: { children: string }) {
  return <Markdown remarkPlugins={[remarkGfm]} components={components}>{children}</Markdown>;
}
