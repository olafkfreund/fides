"use client";

import { useEffect, useRef, useState } from "react";
import { Search, Package, Copy, Check } from "lucide-react";
import { apiGet } from "@/lib/api";

type Artifact = { sha256: string; name: string; type: string; git_commit?: string; created_at?: string };

export default function GlobalSearch() {
  const [q, setQ] = useState("");
  const [results, setResults] = useState<Artifact[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [open, setOpen] = useState(false);
  const [copied, setCopied] = useState("");
  const box = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const onClick = (e: MouseEvent) => { if (box.current && !box.current.contains(e.target as Node)) setOpen(false); };
    document.addEventListener("mousedown", onClick);
    return () => document.removeEventListener("mousedown", onClick);
  }, []);

  useEffect(() => {
    const term = q.trim();
    const isHex = /^[0-9a-f]{4,64}$/i.test(term);
    const t = setTimeout(async () => {
      if (term.length < 2) { setResults(null); return; }
      setLoading(true);
      try {
        const queries = [apiGet<Artifact[]>(`/api/v1/search/artifacts?name=${encodeURIComponent(term)}`)];
        if (isHex) {
          queries.push(apiGet<Artifact[]>(`/api/v1/search/artifacts?sha=${encodeURIComponent(term)}`));
          queries.push(apiGet<Artifact[]>(`/api/v1/search/artifacts?commit=${encodeURIComponent(term)}`));
        }
        const all = (await Promise.all(queries.map((p) => p.catch(() => [] as Artifact[])))).flat();
        const seen = new Set<string>();
        setResults(all.filter((a) => (seen.has(a.sha256) ? false : (seen.add(a.sha256), true))).slice(0, 12));
      } finally { setLoading(false); }
    }, 250);
    return () => clearTimeout(t);
  }, [q]);

  const copy = (sha: string) => { navigator.clipboard?.writeText(sha); setCopied(sha); setTimeout(() => setCopied(""), 1200); };

  return (
    <div ref={box} className="relative w-full max-w-md">
      <div className="flex items-center gap-2 rounded-lg border border-border bg-background px-3 py-2">
        <Search className="size-4 text-muted-foreground" />
        <input
          value={q}
          onChange={(e) => { setQ(e.target.value); setOpen(true); }}
          onFocus={() => setOpen(true)}
          placeholder="Search artifact name, fingerprint, or git commit…"
          className="w-full bg-transparent text-sm outline-none placeholder:text-muted-foreground"
        />
      </div>
      {open && q.trim().length >= 2 && (
        <div className="absolute z-40 mt-2 max-h-96 w-full overflow-auto rounded-lg border border-border bg-card shadow-xl">
          {loading && <div className="px-4 py-3 text-sm text-muted-foreground">Searching…</div>}
          {!loading && results && results.length === 0 && <div className="px-4 py-3 text-sm text-muted-foreground">No matches.</div>}
          {!loading && results && results.map((a) => (
            <button key={a.sha256} onClick={() => copy(a.sha256)} className="flex w-full items-center gap-3 border-b border-border px-4 py-2.5 text-left last:border-b-0 hover:bg-accent">
              <Package className="size-4 shrink-0 text-primary" />
              <div className="min-w-0 flex-1">
                <div className="truncate text-sm font-medium">{a.name} <span className="text-xs font-normal text-muted-foreground">· {a.type}</span></div>
                <div className="truncate font-mono text-xs text-muted-foreground">{a.sha256.slice(0, 20)}… {a.git_commit ? `· ${a.git_commit.slice(0, 10)}` : ""}</div>
              </div>
              {copied === a.sha256 ? <Check className="size-4 text-green-400" /> : <Copy className="size-4 text-muted-foreground" />}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
