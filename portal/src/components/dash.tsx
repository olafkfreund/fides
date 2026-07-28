"use client";

// Fides "Forensic Ledger" design system — the shared primitives that give every
// portal page the same look: mono-uppercase mastheads, gold registration-tick
// panels, and tabular data. Import these instead of re-styling cards per page.

import React from "react";

// PageHeader — the mono-uppercase, letter-spaced masthead on every page.
export function PageHeader({ title, subtitle, right }: { title: string; subtitle?: string; right?: React.ReactNode }) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-3">
      <div>
        <h1 className="font-mono text-lg font-semibold uppercase tracking-[0.2em]">{title}</h1>
        {subtitle && <p className="mt-1 text-sm text-muted-foreground">{subtitle}</p>}
      </div>
      {right}
    </div>
  );
}

// SectionLabel — gold dot + mono uppercase label, used as a panel/section heading.
export function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <h2 className="flex items-center gap-2 text-[11px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">
      <span className="size-1.5 rounded-full bg-primary" />
      {children}
    </h2>
  );
}

// Panel — the signature card: gold corner registration ticks + optional header
// (a SectionLabel on the left, `right` slot on the right).
export function Panel({ label, right, children, className = "" }: { label?: React.ReactNode; right?: React.ReactNode; children: React.ReactNode; className?: string }) {
  return (
    <section className={`relative rounded-xl border border-border bg-card p-5 ${className}`}>
      <span aria-hidden className="pointer-events-none absolute left-2 top-2 size-2 border-l border-t border-primary/60" />
      <span aria-hidden className="pointer-events-none absolute bottom-2 right-2 size-2 border-b border-r border-primary/60" />
      {(label || right) && (
        <div className="mb-4 flex items-center justify-between gap-3">
          {label ? <SectionLabel>{label}</SectionLabel> : <span />}
          {right}
        </div>
      )}
      {children}
    </section>
  );
}

// Ring — a single-value gauge (value is 0..1).
export function Ring({ value, size, stroke, color, children }: { value: number; size: number; stroke: number; color: string; children?: React.ReactNode }) {
  const r = size / 2 - stroke;
  const c = 2 * Math.PI * r;
  return (
    <div className="relative shrink-0" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" strokeWidth={stroke} className="stroke-muted" />
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" strokeWidth={stroke} strokeLinecap="round" stroke={color}
          strokeDasharray={c} strokeDashoffset={c * (1 - Math.max(0, Math.min(1, value)))}
          style={{ transition: "stroke-dashoffset .9s cubic-bezier(.3,.8,.3,1)" }} />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">{children}</div>
    </div>
  );
}

// StatTile — a KPI: big mono number + label, optional icon and link.
export function StatTile({ label, value, sub, icon: Ic, color, href }: { label: string; value: string; sub?: string; icon?: React.ComponentType<{ className?: string }>; color?: string; href?: string }) {
  const body = (
    <>
      <div className="flex items-start justify-between">
        <div>
          <div className={`font-mono text-3xl font-bold tabular-nums leading-none ${color || ""}`}>{value}</div>
          <div className="mt-1.5 text-[9.5px] font-medium uppercase tracking-[0.13em] text-muted-foreground">{label}</div>
        </div>
        {Ic && <span className={`flex size-8 items-center justify-center rounded-lg border border-border bg-muted/40 ${color || "text-primary"}`}><Ic className="size-4" /></span>}
      </div>
      {sub && <div className="mt-3 text-[10.5px] text-muted-foreground">{sub}</div>}
    </>
  );
  const base = "block rounded-xl border border-border bg-card p-4";
  return href
    ? <a href={href} className={`${base} transition-colors hover:border-primary hover:bg-accent`}>{body}</a>
    : <div className={base}>{body}</div>;
}

const CHIP_TONES: Record<string, string> = {
  ok: "border-green-500/40 bg-green-500/10 text-green-400",
  bad: "border-red-500/40 bg-red-500/10 text-red-400",
  warn: "border-amber-500/40 bg-amber-500/10 text-amber-400",
  gold: "border-primary/40 bg-primary/10 text-primary",
  muted: "border-border bg-muted/40 text-muted-foreground",
};

// Chip — a mono-uppercase status pill (verdict, tag, badge).
export function Chip({ children, tone = "muted" }: { children: React.ReactNode; tone?: keyof typeof CHIP_TONES }) {
  return <span className={`inline-block rounded border px-2 py-0.5 font-mono text-[10px] uppercase tracking-[0.1em] ${CHIP_TONES[tone]}`}>{children}</span>;
}

// gridBg — the faint graph-paper background used on data-dense overview pages.
export const gridBg: React.CSSProperties = {
  backgroundImage: "linear-gradient(rgba(128,128,140,0.05) 1px,transparent 1px),linear-gradient(90deg,rgba(128,128,140,0.05) 1px,transparent 1px)",
  backgroundSize: "34px 34px",
};

// Donut — a single-value gauge (value 0..1). Use status green for compliance/
// pass-rate, gold (var(--primary)) for coverage/neutral magnitude. The center
// shows `label` (default: the percentage) + optional `sublabel`.
export function Donut({ value, label, sublabel, color = "#35C08A", size = 148, stroke = 14 }: { value: number; label?: string; sublabel?: string; color?: string; size?: number; stroke?: number }) {
  const r = size / 2 - stroke;
  const c = 2 * Math.PI * r;
  const pct = Math.round(Math.max(0, Math.min(1, value)) * 100);
  return (
    <div className="relative shrink-0" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" strokeWidth={stroke} className="stroke-muted" />
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" strokeWidth={stroke} strokeLinecap="round" stroke={color}
          strokeDasharray={c} strokeDashoffset={c * (1 - Math.max(0, Math.min(1, value)))}
          style={{ transition: "stroke-dashoffset .9s cubic-bezier(.3,.8,.3,1)" }} />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="font-mono text-3xl font-bold tabular-nums" style={{ color }}>{label ?? `${pct}%`}</span>
        {sublabel && <span className="mt-0.5 text-[9px] uppercase tracking-[0.16em] text-muted-foreground">{sublabel}</span>}
      </div>
    </div>
  );
}

// DistBars — a single-hue horizontal distribution ("how many of each"), sorted
// desc, labelled, with the overflow folded into "+ N more". Single hue because
// this encodes MAGNITUDE, not identity — so it needs no categorical palette and
// stays colorblind-safe. Default hue is the gold brand accent.
export function DistBars({ items, color = "var(--primary)", limit = 8 }: { items: { label: string; value: number }[]; color?: string; limit?: number }) {
  const sorted = [...items].sort((a, b) => b.value - a.value);
  const shown = sorted.slice(0, limit);
  const rest = sorted.slice(limit);
  const max = Math.max(1, ...sorted.map((i) => i.value));
  const restSum = rest.reduce((s, i) => s + i.value, 0);
  return (
    <div className="flex flex-col gap-2">
      {shown.map((i) => (
        <div key={i.label} className="flex items-center gap-3 text-xs">
          <span className="w-40 shrink-0 truncate font-mono text-muted-foreground" title={i.label}>{i.label}</span>
          <div className="h-2 flex-1 overflow-hidden rounded-full bg-muted">
            <div className="h-full rounded-full" style={{ width: `${Math.max(2, (i.value / max) * 100)}%`, background: color }} />
          </div>
          <span className="w-8 shrink-0 text-right font-mono tabular-nums text-muted-foreground">{i.value}</span>
        </div>
      ))}
      {rest.length > 0 && <div className="pl-[172px] text-[11px] text-muted-foreground">+ {rest.length} more ({restSum})</div>}
    </div>
  );
}
