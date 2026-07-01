"use client";

import { useEffect, useState } from "react";
import { apiGet, apiPost, api } from "@/lib/api";

const input = "w-full rounded-md border border-neutral-800 bg-neutral-950 px-3 py-2 text-sm font-mono text-neutral-200";
const panel = "rounded-xl border border-neutral-800 bg-neutral-900 p-5";
const btn = "rounded-md bg-purple-600 px-4 py-2 text-sm font-semibold text-white";
const ghost = "rounded-md border border-neutral-700 px-4 py-2 text-sm";

function Msg({ m }: { m: { t: string; ok: boolean } }) {
  return m.t ? <span className={`ml-3 text-sm ${m.ok ? "text-green-400" : "text-red-400"}`}>{m.t}</span> : null;
}

/* ---------- ServiceNow ---------- */
function ServiceNowTab() {
  const [c, setC] = useState<Record<string, unknown>>({ auth_type: "basic", enabled: true });
  const [m, setM] = useState({ t: "", ok: true });
  const load = () => apiGet<Record<string, unknown>>("/api/v1/tenant/servicenow").then((x) => setC({ auth_type: "basic", enabled: true, ...x })).catch((e) => setM({ t: String(e.message), ok: false }));
  useEffect(() => { load(); }, []);
  const save = async () => {
    try { await apiPost("/api/v1/tenant/servicenow", { instance_url: c.instance_url ?? "", auth_type: c.auth_type ?? "basic", client_id: c.client_id ?? "", secret_path: c.secret_path ?? "", enabled: !!c.enabled }); setM({ t: "Saved.", ok: true }); }
    catch (e) { setM({ t: String((e as Error).message), ok: false }); }
  };
  return (
    <div className={panel}>
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        <label className="text-sm"><span className="text-neutral-500">Instance URL</span><input className={input} value={(c.instance_url as string) ?? ""} onChange={(e) => setC({ ...c, instance_url: e.target.value })} placeholder="https://acme.service-now.com" /></label>
        <label className="text-sm"><span className="text-neutral-500">Auth type</span><select className={input} value={(c.auth_type as string) ?? "basic"} onChange={(e) => setC({ ...c, auth_type: e.target.value })}><option value="basic">basic</option><option value="oauth2">oauth2</option></select></label>
        <label className="text-sm"><span className="text-neutral-500">Client ID / Username</span><input className={input} value={(c.client_id as string) ?? ""} onChange={(e) => setC({ ...c, client_id: e.target.value })} /></label>
        <label className="text-sm"><span className="text-neutral-500">Secret reference</span><input className={input} value={(c.secret_path as string) ?? ""} onChange={(e) => setC({ ...c, secret_path: e.target.value })} placeholder="fides/servicenow" /></label>
      </div>
      <label className="mt-4 flex items-center gap-2 text-sm"><input type="checkbox" checked={!!c.enabled} onChange={(e) => setC({ ...c, enabled: e.target.checked })} /> Enabled</label>
      <div className="mt-4"><button onClick={load} className={ghost}>Reload</button> <button onClick={save} className={btn}>Save</button><Msg m={m} /></div>
    </div>
  );
}

/* ---------- Slack ---------- */
function SlackTab() {
  const [secret, setSecret] = useState("");
  const [enabled, setEnabled] = useState(true);
  const [m, setM] = useState({ t: "", ok: true });
  const load = () => apiGet<Record<string, unknown>>("/api/v1/tenant/slack").then((x) => { setSecret((x.webhook_secret_path as string) ?? ""); setEnabled(x.enabled !== false && !!x.webhook_secret_path); }).catch(() => {});
  useEffect(() => { load(); }, []);
  const save = async () => { try { await apiPost("/api/v1/tenant/slack", { webhook_secret_path: secret, enabled }); setM({ t: "Saved.", ok: true }); } catch (e) { setM({ t: String((e as Error).message), ok: false }); } };
  return (
    <div className={panel}>
      <label className="text-sm"><span className="text-neutral-500">Incoming-webhook secret reference</span><input className={input} value={secret} onChange={(e) => setSecret(e.target.value)} placeholder="fides/slack-webhook" /></label>
      <label className="mt-4 flex items-center gap-2 text-sm"><input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} /> Enabled</label>
      <div className="mt-4"><button onClick={save} className={btn}>Save</button><Msg m={m} /></div>
    </div>
  );
}

/* ---------- Service accounts ---------- */
function ServiceAccountsTab() {
  const [list, setList] = useState<{ id: string; name: string; role: string; active_keys: number }[]>([]);
  const [name, setName] = useState(""); const [role, setRole] = useState("Writer");
  const [key, setKey] = useState(""); const [m, setM] = useState({ t: "", ok: true });
  const load = () => apiGet<typeof list>("/api/v1/tenant/service-accounts").then(setList).catch(() => {});
  useEffect(() => { load(); }, []);
  const create = async () => { try { await apiPost("/api/v1/tenant/service-accounts", { name, role }); setName(""); load(); } catch (e) { setM({ t: String((e as Error).message), ok: false }); } };
  const issue = async (id: string) => { try { const r = await apiPost<{ api_key: string }>(`/api/v1/tenant/service-accounts/${id}/keys`, { label: "portal", expires_hours: 0 }); setKey(r.api_key); load(); } catch (e) { setM({ t: String((e as Error).message), ok: false }); } };
  return (
    <div className={panel}>
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
        <input className={input} value={name} onChange={(e) => setName(e.target.value)} placeholder="name" />
        <select className={input} value={role} onChange={(e) => setRole(e.target.value)}><option>Writer</option><option>Admin</option><option>Auditor</option><option>Viewer</option></select>
        <button onClick={create} className={btn}>Create</button>
      </div>
      <Msg m={m} />
      {key && <pre className="mt-3 rounded-md border border-neutral-800 bg-neutral-950 p-3 text-xs text-green-400">Save this key now (shown once):{"\n"}{key}</pre>}
      {list.length > 0 && (
        <table className="mt-4 w-full text-left text-sm font-mono">
          <thead className="text-neutral-500"><tr><th className="py-1">Name</th><th>Role</th><th>Keys</th><th></th></tr></thead>
          <tbody>{list.map((a) => <tr key={a.id} className="border-t border-neutral-800"><td className="py-2">{a.name}</td><td>{a.role}</td><td>{a.active_keys}</td><td><button onClick={() => issue(a.id)} className={ghost}>Issue key</button></td></tr>)}</tbody>
        </table>
      )}
    </div>
  );
}

/* ---------- Users ---------- */
function UsersTab() {
  const [users, setUsers] = useState<{ id: string; name: string; email: string; role: string }[]>([]);
  const [pw, setPw] = useState<Record<string, string>>({}); const [m, setM] = useState({ t: "", ok: true });
  useEffect(() => { apiGet<typeof users>("/api/v1/tenant/users").then(setUsers).catch(() => {}); }, []);
  const setPass = async (id: string) => { try { await apiPost(`/api/v1/tenant/users/${id}/password`, { password: pw[id] || "" }); setM({ t: "Password set.", ok: true }); } catch (e) { setM({ t: String((e as Error).message), ok: false }); } };
  return (
    <div className={panel}>
      {users.length ? (
        <table className="w-full text-left text-sm">
          <thead className="text-neutral-500"><tr><th className="py-1">Name</th><th>Email</th><th>Role</th><th>Set password</th></tr></thead>
          <tbody>{users.map((u) => (
            <tr key={u.id} className="border-t border-neutral-800">
              <td className="py-2">{u.name}</td><td className="font-mono text-neutral-400">{u.email}</td><td>{u.role}</td>
              <td className="flex gap-2 py-2"><input className={input} type="password" placeholder="new password" onChange={(e) => setPw({ ...pw, [u.id]: e.target.value })} /><button onClick={() => setPass(u.id)} className={ghost}>Set</button></td>
            </tr>
          ))}</tbody>
        </table>
      ) : <p className="text-sm text-neutral-500">No users.</p>}
      <Msg m={m} />
    </div>
  );
}

/* ---------- Git & Webhooks ---------- */
function GitWebhooksTab() {
  const [gp, setGp] = useState<Record<string, string>>({ provider: "github" });
  const [wh, setWh] = useState<Record<string, string>>({});
  const [m, setM] = useState({ t: "", ok: true });
  const saveGit = async () => { try { await apiPost("/api/v1/tenant/git-providers", { provider: gp.provider || "github", host: gp.host || "", api_base: gp.api_base || "", token_path: gp.token_path || "", inbound_secret_path: gp.inbound_secret_path || "", enabled: true }); setM({ t: "Git provider saved.", ok: true }); } catch (e) { setM({ t: String((e as Error).message), ok: false }); } };
  const saveHook = async () => { try { await api("POST", "/api/v1/tenant/webhooks", { name: wh.name || "", url: wh.url || "", secret_path: wh.secret_path || "", event_types: [], enabled: true }); setM({ t: "Webhook saved.", ok: true }); } catch (e) { setM({ t: String((e as Error).message), ok: false }); } };
  return (
    <div className="flex flex-col gap-5">
      <div className={panel}>
        <h3 className="mb-3 text-xs uppercase tracking-wide text-neutral-500">Git provider</h3>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <select className={input} value={gp.provider} onChange={(e) => setGp({ ...gp, provider: e.target.value })}><option>github</option><option>gitlab</option></select>
          <input className={input} placeholder="host (github.com)" onChange={(e) => setGp({ ...gp, host: e.target.value })} />
          <input className={input} placeholder="api base" onChange={(e) => setGp({ ...gp, api_base: e.target.value })} />
          <input className={input} placeholder="token reference" onChange={(e) => setGp({ ...gp, token_path: e.target.value })} />
          <input className={input} placeholder="inbound secret ref (optional)" onChange={(e) => setGp({ ...gp, inbound_secret_path: e.target.value })} />
        </div>
        <div className="mt-3"><button onClick={saveGit} className={btn}>Save provider</button></div>
      </div>
      <div className={panel}>
        <h3 className="mb-3 text-xs uppercase tracking-wide text-neutral-500">Outbound webhook</h3>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <input className={input} placeholder="name" onChange={(e) => setWh({ ...wh, name: e.target.value })} />
          <input className={input} placeholder="https url" onChange={(e) => setWh({ ...wh, url: e.target.value })} />
          <input className={input} placeholder="signing secret ref" onChange={(e) => setWh({ ...wh, secret_path: e.target.value })} />
        </div>
        <div className="mt-3"><button onClick={saveHook} className={btn}>Save webhook</button><Msg m={m} /></div>
      </div>
    </div>
  );
}

const TABS = [
  { id: "servicenow", label: "ServiceNow", el: <ServiceNowTab /> },
  { id: "slack", label: "Slack", el: <SlackTab /> },
  { id: "accounts", label: "Service Accounts", el: <ServiceAccountsTab /> },
  { id: "git", label: "Git & Webhooks", el: <GitWebhooksTab /> },
  { id: "users", label: "Users", el: <UsersTab /> },
];

export default function Settings() {
  const [tab, setTab] = useState("servicenow");
  return (
    <div className="max-w-4xl">
      <h1 className="text-xl font-semibold">Settings</h1>
      <p className="mt-1 text-sm text-neutral-500">Integrations, credentials, and user management.</p>
      <div className="mt-4 flex gap-1 border-b border-neutral-800">
        {TABS.map((t) => (
          <button key={t.id} onClick={() => setTab(t.id)} className={`px-4 py-2 text-sm ${tab === t.id ? "border-b-2 border-purple-500 text-neutral-100" : "text-neutral-400"}`}>{t.label}</button>
        ))}
      </div>
      <div className="mt-5">{TABS.find((t) => t.id === tab)?.el}</div>
    </div>
  );
}
