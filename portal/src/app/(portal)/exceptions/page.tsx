"use client";

import { useEffect, useState } from "react";
import { apiGet, apiPost } from "@/lib/api";

type Exception = {
  id: string;
  control_key: string;
  reason: string;
  approved_by: string;
  created_at: string;
  expires_at: string;
  revoked: boolean;
  active: boolean;
};

function statusOf(e: Exception): { label: string; cls: string } {
  if (e.revoked) return { label: "revoked", cls: "text-muted-foreground" };
  if (!e.active) return { label: "expired", cls: "text-muted-foreground" };
  return { label: "active", cls: "text-primary" };
}

export default function Exceptions() {
  const [items, setItems] = useState<Exception[]>([]);
  const [err, setErr] = useState("");
  const [ctrl, setCtrl] = useState("");
  const [reason, setReason] = useState("");
  const [days, setDays] = useState("30");
  const [by, setBy] = useState("");

  const load = () =>
    apiGet<Exception[]>("/api/v1/exceptions")
      .then((x) => setItems(x ?? []))
      .catch((e) => setErr(String((e as Error).message || e)));
  useEffect(() => {
    load();
  }, []);

  const create = async () => {
    setErr("");
    try {
      await apiPost("/api/v1/exceptions", {
        control_key: ctrl,
        reason,
        approved_by: by,
        expires_in_days: Number(days) || 0,
      });
      setCtrl("");
      setReason("");
      setBy("");
      load();
    } catch (e) {
      setErr(String((e as Error).message || e));
    }
  };

  const revoke = async (id: string) => {
    setErr("");
    try {
      await apiPost(`/api/v1/exceptions/${id}/revoke`, {});
      load();
    } catch (e) {
      setErr(String((e as Error).message || e));
    }
  };

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Control Exceptions</h1>
        <p className="text-muted-foreground text-sm">
          Governed, time-boxed waivers. An <span className="text-primary">active</span> exception lets the
          change-gate treat its control as waived instead of blocking. Every waiver expires.
        </p>
      </div>

      {err && <div className="text-sm text-muted-foreground border border-border rounded p-2">{err}</div>}

      <div className="rounded-lg border border-border bg-card p-4 grid gap-2 md:grid-cols-5 items-end">
        <label className="flex flex-col gap-1 text-sm md:col-span-1">
          <span className="text-muted-foreground">Control key</span>
          <input value={ctrl} onChange={(e) => setCtrl(e.target.value)} placeholder="SOC2-CC6.1"
            className="rounded border border-border bg-background px-2 py-1" />
        </label>
        <label className="flex flex-col gap-1 text-sm md:col-span-2">
          <span className="text-muted-foreground">Reason</span>
          <input value={reason} onChange={(e) => setReason(e.target.value)} placeholder="risk accepted by …"
            className="rounded border border-border bg-background px-2 py-1" />
        </label>
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-muted-foreground">Expires (days)</span>
          <input value={days} onChange={(e) => setDays(e.target.value)} type="number"
            className="rounded border border-border bg-background px-2 py-1" />
        </label>
        <button onClick={create} disabled={!ctrl || !reason}
          className="rounded bg-primary/15 text-primary border border-border px-3 py-1 text-sm disabled:opacity-50">
          Add waiver
        </button>
      </div>

      <div className="rounded-lg border border-border bg-card overflow-x-auto">
        <table className="w-full text-sm">
          <thead className="text-muted-foreground border-b border-border">
            <tr>
              <th className="text-left p-2">Control</th>
              <th className="text-left p-2">Reason</th>
              <th className="text-left p-2">Approved by</th>
              <th className="text-left p-2">Expires</th>
              <th className="text-left p-2">Status</th>
              <th className="p-2"></th>
            </tr>
          </thead>
          <tbody>
            {items.length === 0 && (
              <tr>
                <td colSpan={6} className="p-3 text-muted-foreground">No exceptions.</td>
              </tr>
            )}
            {items.map((e) => {
              const st = statusOf(e);
              return (
                <tr key={e.id} className="border-b border-border last:border-0">
                  <td className="p-2 font-mono">{e.control_key}</td>
                  <td className="p-2">{e.reason}</td>
                  <td className="p-2 text-muted-foreground">{e.approved_by || "—"}</td>
                  <td className="p-2 text-muted-foreground">{new Date(e.expires_at).toLocaleDateString()}</td>
                  <td className={`p-2 ${st.cls}`}>{st.label}</td>
                  <td className="p-2 text-right">
                    {st.label === "active" && (
                      <button onClick={() => revoke(e.id)}
                        className="text-xs text-muted-foreground hover:text-foreground border border-border rounded px-2 py-0.5">
                        Revoke
                      </button>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
