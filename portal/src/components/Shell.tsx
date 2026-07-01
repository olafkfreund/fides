"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { useTheme } from "next-themes";
import {
  Moon, Sun, ShieldCheck, LineChart, GitBranch, Archive, Server, Scale,
  ListChecks, MessageSquare, Gauge, Settings as SettingsIcon, BookOpen, LogOut, UserCircle2,
} from "lucide-react";
import { apiGet, ApiError } from "@/lib/api";

type Icon = React.ComponentType<{ className?: string }>;
type NavItem = { href: string; label: string; icon: Icon };

const NAV: NavItem[] = [
  { href: "/", label: "Overview", icon: LineChart },
  { href: "/flows", label: "Flows & Trails", icon: GitBranch },
  { href: "/artifacts", label: "Artifacts & SBOM", icon: Archive },
  { href: "/environments", label: "Environments", icon: Server },
  { href: "/policies", label: "Policies", icon: Scale },
  { href: "/controls", label: "Controls", icon: ListChecks },
  { href: "/ai-audits", label: "AI Audits", icon: MessageSquare },
  { href: "/telemetry", label: "Telemetry", icon: Gauge },
  { href: "/settings", label: "Settings", icon: SettingsIcon },
  { href: "/help", label: "Help & Docs", icon: BookOpen },
];

function ThemeToggle() {
  const { resolvedTheme, setTheme } = useTheme();
  const [mounted, setMounted] = useState(false);
  // eslint-disable-next-line react-hooks/set-state-in-effect -- idiomatic next-themes hydration guard
  useEffect(() => setMounted(true), []);
  const dark = resolvedTheme === "dark";
  return (
    <button
      onClick={() => setTheme(dark ? "light" : "dark")}
      className="flex items-center gap-2 rounded-md px-3 py-2 text-sm text-muted-foreground hover:text-foreground"
      aria-label="Toggle theme"
    >
      {mounted && dark ? <Sun className="size-4" /> : <Moon className="size-4" />}
      <span>{mounted ? (dark ? "Light mode" : "Dark mode") : "Theme"}</span>
    </button>
  );
}

export default function Shell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const [authed, setAuthed] = useState<boolean | null>(null);

  useEffect(() => {
    apiGet("/api/v1/flows")
      .then(() => setAuthed(true))
      .catch((e) => {
        if (e instanceof ApiError && e.status === 401) router.replace("/login");
        else setAuthed(true);
      });
  }, [router]);

  if (authed === null) {
    return <div className="m-auto text-muted-foreground text-sm">Loading…</div>;
  }

  return (
    <div className="flex min-h-full w-full">
      <aside className="flex w-60 shrink-0 flex-col border-r border-sidebar-border bg-sidebar p-4 text-sidebar-foreground">
        <div className="mb-6 flex items-center gap-2 px-1">
          <ShieldCheck className="size-6 text-primary" />
          <span className="font-mono text-lg font-bold tracking-wide">FIDES</span>
        </div>
        <nav className="flex flex-1 flex-col gap-1">
          {NAV.map((n) => {
            const active = pathname === n.href;
            const Ic = n.icon;
            return (
              <Link
                key={n.href}
                href={n.href}
                className={`flex items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors ${active ? "bg-primary/15 font-medium text-foreground" : "text-muted-foreground hover:bg-accent hover:text-foreground"}`}
              >
                <Ic className={`size-4 ${active ? "text-primary" : ""}`} />
                {n.label}
              </Link>
            );
          })}
        </nav>
        <div className="mt-2 flex flex-col gap-1 border-t border-sidebar-border pt-2">
          <ThemeToggle />
          <div className="flex items-center justify-between px-3 py-2">
            <div className="flex items-center gap-2">
              <UserCircle2 className="size-6 text-muted-foreground" />
              <div className="leading-tight">
                <div className="text-sm">Admin</div>
                <div className="text-xs text-muted-foreground">Signed in</div>
              </div>
            </div>
            <a href="/login" title="Sign out" className="text-muted-foreground hover:text-foreground"><LogOut className="size-4" /></a>
          </div>
        </div>
      </aside>
      <main className="flex-1 p-8">{children}</main>
    </div>
  );
}
