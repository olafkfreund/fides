"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { apiGet, ApiError } from "@/lib/api";

type NavItem = { href: string; label: string; ready?: boolean };

const NAV: NavItem[] = [
  { href: "/", label: "Overview", ready: true },
  { href: "/settings", label: "Settings", ready: true },
  { href: "/flows", label: "Flows & Trails", ready: true },
  { href: "/artifacts", label: "Artifacts & SBOM" },
  { href: "/environments", label: "Environments", ready: true },
  { href: "/policies", label: "Policies" },
  { href: "/ai-audits", label: "AI Audits" },
  { href: "/telemetry", label: "Telemetry" },
];

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
    return <div className="m-auto text-neutral-500 text-sm">Loading…</div>;
  }

  return (
    <div className="flex min-h-full w-full">
      <aside className="w-56 shrink-0 border-r border-neutral-800 p-4">
        <div className="mb-6 font-mono font-semibold tracking-wide">FIDES</div>
        <nav className="flex flex-col gap-1">
          {NAV.map((n) => {
            const active = pathname === n.href;
            const base = "rounded-md px-3 py-2 text-sm";
            if (!n.ready) {
              return (
                <span key={n.href} className={`${base} text-neutral-600 cursor-not-allowed`} title="Coming soon">
                  {n.label}
                </span>
              );
            }
            return (
              <Link
                key={n.href}
                href={n.href}
                className={`${base} ${active ? "bg-purple-600/15 text-neutral-100" : "text-neutral-400 hover:text-neutral-100"}`}
              >
                {n.label}
              </Link>
            );
          })}
        </nav>
      </aside>
      <main className="flex-1 p-8">{children}</main>
    </div>
  );
}
