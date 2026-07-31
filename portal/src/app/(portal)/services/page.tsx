"use client";

import { useEffect, useState } from "react";
import { apiGet, apiPost } from "@/lib/api";

type Service = {
  service: string;
  owner: string;
  on_call: string;
  audit_contact: string;
  tier: number;
};

export default function Services() {
  const [items, setItems] = useState<Service[]>([]);
  const [err, setErr] = useState("");
  const [name, setName] = useState("");
  const [owner, setOwner] = useState("");
  const [onCall, setOnCall] = useState("");
  const [audit, setAudit] = useState("");
  const [tier, setTier] = useState("1");

  const load = () =>
    apiGet<Service[]>("/api/v1/services")
      .then((x) => setItems(x ?? []))
      .catch((e) => setErr(String((e as Error).message || e)));
  useEffect(() => {
    load();
  }, []);

  const save = async () => {
    setErr("");
    try {
      await apiPost("/api/v1/services", {
        service: name,
        owner,
        on_call: onCall,
        audit_contact: audit,
        tier: Number(tier) || 1,
      });
      setName("");
      setOwner("");
      setOnCall("");
      setAudit("");
      load();
    } catch (e) {
      setErr(String((e as Error).message || e));
    }
  };

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Services</h1>
        <p className="text-muted-foreground text-sm">
          Ownership registry — who owns, is on-call for, and is audit-responsible for each service.
          The <span className="text-primary">tier</span> (1–3) scales which controls apply (controls with
          <span className="font-mono"> level ≤ tier</span>).
        </p>
      </div>

      {err && <div className="text-sm text-muted-foreground border border-border rounded p-2">{err}</div>}

      <div className="rounded-lg border border-border bg-card p-4 grid gap-2 md:grid-cols-6 items-end">
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-muted-foreground">Service</span>
          <input value={name} onChange={(e) => setName(e.target.value)} placeholder="checkout-api"
            className="rounded border border-border bg-background px-2 py-1" />
        </label>
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-muted-foreground">Owner</span>
          <input value={owner} onChange={(e) => setOwner(e.target.value)}
            className="rounded border border-border bg-background px-2 py-1" />
        </label>
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-muted-foreground">On-call</span>
          <input value={onCall} onChange={(e) => setOnCall(e.target.value)}
            className="rounded border border-border bg-background px-2 py-1" />
        </label>
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-muted-foreground">Audit contact</span>
          <input value={audit} onChange={(e) => setAudit(e.target.value)}
            className="rounded border border-border bg-background px-2 py-1" />
        </label>
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-muted-foreground">Tier</span>
          <select value={tier} onChange={(e) => setTier(e.target.value)}
            className="rounded border border-border bg-background px-2 py-1">
            <option value="1">1</option>
            <option value="2">2</option>
            <option value="3">3</option>
          </select>
        </label>
        <button onClick={save} disabled={!name}
          className="rounded bg-primary/15 text-primary border border-border px-3 py-1 text-sm disabled:opacity-50">
          Save
        </button>
      </div>

      <div className="rounded-lg border border-border bg-card overflow-x-auto">
        <table className="w-full text-sm">
          <thead className="text-muted-foreground border-b border-border">
            <tr>
              <th className="text-left p-2">Service</th>
              <th className="text-left p-2">Owner</th>
              <th className="text-left p-2">On-call</th>
              <th className="text-left p-2">Audit</th>
              <th className="text-left p-2">Tier</th>
            </tr>
          </thead>
          <tbody>
            {items.length === 0 && (
              <tr><td colSpan={5} className="p-3 text-muted-foreground">No services registered.</td></tr>
            )}
            {items.map((s) => (
              <tr key={s.service} className="border-b border-border last:border-0">
                <td className="p-2 font-medium">{s.service}</td>
                <td className="p-2 text-muted-foreground">{s.owner || "—"}</td>
                <td className="p-2 text-muted-foreground">{s.on_call || "—"}</td>
                <td className="p-2 text-muted-foreground">{s.audit_contact || "—"}</td>
                <td className="p-2 text-primary">{s.tier}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
