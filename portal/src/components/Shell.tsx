"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { useTheme } from "next-themes";
import { Moon, Sun, ShieldCheck } from "lucide-react";
import { apiGet, ApiError } from "@/lib/api";

type NavItem = { href: string; label: string; ready?: boolean };

const NAV: NavItem[] = [
  { href: "/", label: "Overview", ready: true },
  { href: "/settings", label: "Settings", ready: true },
  { href: "/flows", label: "Flows & Trails", ready: true },
  { href: "/artifacts", label: "Artifacts & SBOM", ready: true },
  { href: "/environments", label: "Environments", ready: true },
  { href: "/policies", label: "Policies", ready: true },
  { href: "/controls", label: "Controls", ready: true },
  { href: "/ai-audits", label: "AI Audits", ready: true },
  { href: "/telemetry", label: "Telemetry", ready: true },
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
      className="mt-2 flex items-center gap-2 rounded-md px-3 py-2 text-sm text-muted-foreground hover:text-foreground"
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
    // Cheap authenticated call to confirm the session.
    apiGet("/api/v1/flows")
      .then(() => setAuthed(true))
      .catch((e) => {
        if (e instanceof ApiError && e.status === 401) {
          router.replace("/login");
        } else {
          setAuthed(true); // reachable but errored for another reason
        }
      });
  }, [router]);

  if (authed === null) {
    return <div className="m-auto text-muted-foreground text-sm">Loading…</div>;
  }

  return (
    <div className="flex min-h-full w-full">
      <aside className="flex w-56 shrink-0 flex-col border-r border-sidebar-border bg-sidebar p-4 text-sidebar-foreground">
        <div className="mb-6 flex items-center gap-2 px-1">
          <ShieldCheck className="size-5 text-primary" />
          <span className="font-mono text-lg font-bold tracking-wide">FIDES</span>
        </div>
        <nav className="flex flex-1 flex-col gap-1">
          {NAV.map((n) => {
            const active = pathname === n.href;
            const base = "rounded-md px-3 py-2 text-sm transition-colors";
            if (!n.ready) {
              return (
                <span key={n.href} className={`${base} text-muted-foreground/60 cursor-not-allowed`} title="Coming soon">
                  {n.label}
                </span>
              );
            }
            return (
              <Link
                key={n.href}
                href={n.href}
                className={`${base} ${active ? "bg-primary/15 font-medium text-foreground" : "text-muted-foreground hover:bg-accent hover:text-foreground"}`}
              >
                {n.label}
              </Link>
            );
          })}
        </nav>
        <div className="border-t border-sidebar-border pt-2">
          <ThemeToggle />
        </div>
      </aside>
      <main className="flex-1 p-8">{children}</main>
    </div>
  );
}
