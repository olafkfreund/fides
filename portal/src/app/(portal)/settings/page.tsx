"use client";

import { useEffect, useState } from "react";
import { apiGet, apiPost } from "@/lib/api";

type SNConfig = {
  instance_url?: string;
  auth_type?: string;
  client_id?: string;
  secret_path?: string;
  enabled?: boolean;
};

const input =
  "w-full rounded-md border border-neutral-800 bg-neutral-950 px-3 py-2 text-sm font-mono text-neutral-200";

export default function Settings() {
  const [cfg, setCfg] = useState<SNConfig>({ auth_type: "basic", enabled: true });
  const [msg, setMsg] = useState<{ text: string; ok: boolean }>({ text: "", ok: true });

  const load = () =>
    apiGet<SNConfig>("/api/v1/tenant/servicenow")
      .then((c) => setCfg({ auth_type: "basic", enabled: true, ...c }))
      .catch((e) => setMsg({ text: String(e.message || e), ok: false }));

  useEffect(() => {
    load();
  }, []);

  const save = async () => {
    try {
      await apiPost("/api/v1/tenant/servicenow", {
        instance_url: cfg.instance_url ?? "",
        auth_type: cfg.auth_type ?? "basic",
        client_id: cfg.client_id ?? "",
        secret_path: cfg.secret_path ?? "",
        enabled: !!cfg.enabled,
      });
      setMsg({ text: "Saved.", ok: true });
    } catch (e) {
      setMsg({ text: String((e as Error).message || e), ok: false });
    }
  };

  return (
    <div className="max-w-3xl">
      <h1 className="text-xl font-semibold">Settings</h1>
      <p className="mt-1 text-sm text-neutral-500">ServiceNow integration (CMDB · ITOM · ITSM).</p>

      <div className="mt-6 rounded-xl border border-neutral-800 bg-neutral-900 p-5">
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <label className="text-sm">
            <span className="text-neutral-500">Instance URL</span>
            <input className={input} value={cfg.instance_url ?? ""} onChange={(e) => setCfg({ ...cfg, instance_url: e.target.value })} placeholder="https://acme.service-now.com" />
          </label>
          <label className="text-sm">
            <span className="text-neutral-500">Auth type</span>
            <select className={input} value={cfg.auth_type ?? "basic"} onChange={(e) => setCfg({ ...cfg, auth_type: e.target.value })}>
              <option value="basic">basic</option>
              <option value="oauth2">oauth2</option>
            </select>
          </label>
          <label className="text-sm">
            <span className="text-neutral-500">Client ID / Username</span>
            <input className={input} value={cfg.client_id ?? ""} onChange={(e) => setCfg({ ...cfg, client_id: e.target.value })} />
          </label>
          <label className="text-sm">
            <span className="text-neutral-500">Secret reference</span>
            <input className={input} value={cfg.secret_path ?? ""} onChange={(e) => setCfg({ ...cfg, secret_path: e.target.value })} placeholder="fides/servicenow" />
          </label>
        </div>
        <label className="mt-4 flex items-center gap-2 text-sm">
          <input type="checkbox" checked={!!cfg.enabled} onChange={(e) => setCfg({ ...cfg, enabled: e.target.checked })} />
          Enabled
        </label>
        <div className="mt-4 flex items-center gap-3">
          <button onClick={load} className="rounded-md border border-neutral-700 px-4 py-2 text-sm">Reload</button>
          <button onClick={save} className="rounded-md bg-purple-600 px-4 py-2 text-sm font-semibold text-white">Save</button>
          {msg.text && <span className={`text-sm ${msg.ok ? "text-green-400" : "text-red-400"}`}>{msg.text}</span>}
        </div>
      </div>
    </div>
  );
}
