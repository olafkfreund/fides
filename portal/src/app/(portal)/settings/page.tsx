"use client";

import { useEffect, useState } from "react";
import { apiGet, apiPost, api } from "@/lib/api";

const input = "w-full rounded-md border border-border bg-background px-3 py-2 text-sm font-mono text-foreground";
const panel = "rounded-xl border border-border bg-card p-5";
const btn = "rounded-md bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground";
const ghost = "rounded-md border border-border px-4 py-2 text-sm";

function Msg({ m }: { m: { t: string; ok: boolean } }) {
  return m.t ? <span className={`ml-3 text-sm ${m.ok ? "text-green-400" : "text-red-400"}`}>{m.t}</span> : null;
}

type Dict = Record<string, unknown>;
function Field({ label, obj, set, k, ph, type }: { label: string; obj: Dict; set: (o: Dict) => void; k: string; ph?: string; type?: string }) {
  return (
    <label className="text-sm">
      <span className="text-muted-foreground">{label}</span>
      <input className={input} type={type || "text"} value={(obj[k] as string) ?? ""} placeholder={ph} onChange={(e) => set({ ...obj, [k]: e.target.value })} />
    </label>
  );
}

/* ---------- Infrastructure: SSO, Storage, Vault, LLM ---------- */
function InfrastructureTab() {
  const [auth, setAuth] = useState<Dict>({ provider_name: "github", enabled: false });
  const [storage, setStorage] = useState<Dict>({ storage_driver: "local" });
  const [vault, setVault] = useState<Dict>({ vault_provider: "none" });
  const [llm, setLlm] = useState<Dict>({ provider_name: "anthropic" });
  const [m, setM] = useState({ t: "", ok: true });

  const load = () => apiGet<{ auth?: Dict; storage?: Dict; vault?: Dict; llm?: Dict }>("/api/v1/tenant/settings").then((s) => {
    if (s.auth) setAuth(s.auth); if (s.storage) setStorage(s.storage); if (s.vault) setVault(s.vault); if (s.llm) setLlm(s.llm);
  }).catch((e) => setM({ t: String(e.message), ok: false }));
  useEffect(() => { load(); }, []);

  const save = async () => {
    try { await apiPost("/api/v1/tenant/settings", { auth, storage, vault, llm }); setM({ t: "Saved.", ok: true }); }
    catch (e) { setM({ t: String((e as Error).message), ok: false }); }
  };

  return (
    <div className="flex flex-col gap-5">
      <div className={panel}>
        <h3 className="mb-3 text-xs font-semibold uppercase tracking-wide text-muted-foreground">SSO &amp; OAuth</h3>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <label className="text-sm"><span className="text-muted-foreground">Identity Provider</span>
            <select className={input} value={(auth.provider_name as string) ?? "github"} onChange={(e) => setAuth({ ...auth, provider_name: e.target.value })}>
              <option value="github">github</option><option value="google">google</option><option value="okta">okta</option><option value="azure">azure</option><option value="generic">generic OIDC</option>
            </select>
          </label>
          <Field label="Client ID" obj={auth} set={setAuth} k="client_id" ph="your OIDC/OAuth client id" />
          <Field label="Client Secret Reference Path" obj={auth} set={setAuth} k="client_secret_path" ph="fides/oauth-secret" />
          <Field label="Redirect URI" obj={auth} set={setAuth} k="redirect_uri" ph="https://.../api/v1/auth/callback" />
          <Field label="Auth URL" obj={auth} set={setAuth} k="auth_url" ph="https://github.com/login/oauth/authorize" />
          <Field label="Token URL" obj={auth} set={setAuth} k="token_url" ph="https://github.com/login/oauth/access_token" />
          <Field label="Userinfo URL" obj={auth} set={setAuth} k="userinfo_url" ph="https://api.github.com/user" />
        </div>
        <label className="mt-3 flex items-center gap-2 text-sm"><input type="checkbox" checked={!!auth.enabled} onChange={(e) => setAuth({ ...auth, enabled: e.target.checked })} /> Enable SSO Login</label>
      </div>

      <div className={panel}>
        <h3 className="mb-3 text-xs font-semibold uppercase tracking-wide text-muted-foreground">Evidence Storage</h3>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <label className="text-sm"><span className="text-muted-foreground">Storage Driver</span>
            <select className={input} value={(storage.storage_driver as string) ?? "local"} onChange={(e) => setStorage({ ...storage, storage_driver: e.target.value })}>
              <option value="local">local</option><option value="s3">s3</option><option value="gcs">gcs</option><option value="azure">azure</option>
            </select>
          </label>
          <Field label="Endpoint URL" obj={storage} set={setStorage} k="s3_endpoint" ph="https://s3.eu-west-2.amazonaws.com" />
          <Field label="Bucket / Container Name" obj={storage} set={setStorage} k="s3_bucket" ph="fides-evidence-synechron" />
          <Field label="Region" obj={storage} set={setStorage} k="s3_region" ph="eu-west-2" />
          <Field label="Access Key Reference" obj={storage} set={setStorage} k="s3_access_key_path" ph="fides/aws-access-key" />
          <Field label="Secret Key Reference" obj={storage} set={setStorage} k="s3_secret_key_path" ph="fides/aws-secret-key" />
          <Field label="GCS Bucket" obj={storage} set={setStorage} k="gcs_bucket" />
          <Field label="GCS Credentials Ref" obj={storage} set={setStorage} k="gcs_credentials_path" />
          <Field label="Azure Container" obj={storage} set={setStorage} k="azure_container" />
          <Field label="Azure Connection Ref" obj={storage} set={setStorage} k="azure_connection_string_path" />
        </div>
      </div>

      <div className={panel}>
        <h3 className="mb-3 text-xs font-semibold uppercase tracking-wide text-muted-foreground">Secret Key Engines</h3>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <label className="text-sm"><span className="text-muted-foreground">Vault Provider</span>
            <select className={input} value={(vault.vault_provider as string) ?? "none"} onChange={(e) => setVault({ ...vault, vault_provider: e.target.value })}>
              <option value="none">none</option><option value="hashicorp">hashicorp</option><option value="aws">aws</option><option value="azure">azure</option>
            </select>
          </label>
          <Field label="Vault Address" obj={vault} set={setVault} k="vault_address" ph="https://secretsmanager.eu-west-2.amazonaws.com" />
          <Field label="Token / Auth Reference Path" obj={vault} set={setVault} k="vault_token_path" ph="fides/vault-token (or IRSA)" />
          <Field label="IAM / AppRole Role Name" obj={vault} set={setVault} k="vault_role" ph="fides-secrets-reader" />
        </div>
      </div>

      <div className={panel}>
        <h3 className="mb-3 text-xs font-semibold uppercase tracking-wide text-muted-foreground">LLM Configuration</h3>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <label className="text-sm"><span className="text-muted-foreground">LLM Provider</span>
            <select className={input} value={(llm.provider_name as string) ?? "ollama"} onChange={(e) => setLlm({ ...llm, provider_name: e.target.value })}>
              <option value="ollama">ollama (self-hosted)</option><option value="anthropic">anthropic</option><option value="openai">openai</option><option value="bedrock">bedrock (AWS)</option><option value="azure">azure</option>
            </select>
          </label>
          <Field label="Model Name" obj={llm} set={setLlm} k="model_name" ph="claude-opus-4-8" />
          <Field label="Endpoint URL" obj={llm} set={setLlm} k="endpoint_url" ph="http://fides-ollama:11434" />
          <Field label="API Key Reference" obj={llm} set={setLlm} k="api_key_path" ph="fides/llm-api-key" />
          <Field label="AWS Region" obj={llm} set={setLlm} k="aws_region" ph="us-east-1" />
          <Field label="Azure Deployment" obj={llm} set={setLlm} k="azure_deployment" />
        </div>
      </div>

      <div><button onClick={load} className={ghost}>Reload</button> <button onClick={save} className={btn}>Save Configuration</button><Msg m={m} /></div>
    </div>
  );
}

/* ---------- User Directory & Group Mappings ---------- */
function DirectoryTab() {
  const [maps, setMaps] = useState<{ id: string; external_group: string; role: string }[]>([]);
  const [group, setGroup] = useState(""); const [role, setRole] = useState("Viewer");
  const [m, setM] = useState({ t: "", ok: true });
  const load = () => apiGet<typeof maps>("/api/v1/tenant/group-mappings").then(setMaps).catch(() => {});
  useEffect(() => { load(); }, []);
  const add = async () => {
    try { await apiPost("/api/v1/tenant/group-mappings", { external_group: group, role }); setGroup(""); load(); setM({ t: "Mapping saved.", ok: true }); }
    catch (e) { setM({ t: String((e as Error).message), ok: false }); }
  };
  return (
    <div className={panel}>
      <h3 className="mb-3 text-xs font-semibold uppercase tracking-wide text-muted-foreground">Map an SSO/IdP group to a Fides role</h3>
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
        <input className={input} value={group} onChange={(e) => setGroup(e.target.value)} placeholder="external group (e.g. platform-admins)" />
        <select className={input} value={role} onChange={(e) => setRole(e.target.value)}><option>Admin</option><option>Writer</option><option>Auditor</option><option>Viewer</option></select>
        <button onClick={add} className={btn}>Add mapping</button>
      </div>
      <Msg m={m} />
      {maps.length > 0 && (
        <table className="mt-4 w-full text-left text-sm font-mono">
          <thead className="text-muted-foreground"><tr><th className="py-1">External group</th><th>Role</th></tr></thead>
          <tbody>{maps.map((g) => <tr key={g.id} className="border-t border-border"><td className="py-2">{g.external_group}</td><td>{g.role}</td></tr>)}</tbody>
        </table>
      )}
    </div>
  );
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
        <label className="text-sm"><span className="text-muted-foreground">Instance URL</span><input className={input} value={(c.instance_url as string) ?? ""} onChange={(e) => setC({ ...c, instance_url: e.target.value })} placeholder="https://acme.service-now.com" /></label>
        <label className="text-sm"><span className="text-muted-foreground">Auth type</span><select className={input} value={(c.auth_type as string) ?? "basic"} onChange={(e) => setC({ ...c, auth_type: e.target.value })}><option value="basic">basic</option><option value="oauth2">oauth2</option></select></label>
        <label className="text-sm"><span className="text-muted-foreground">Client ID / Username</span><input className={input} value={(c.client_id as string) ?? ""} onChange={(e) => setC({ ...c, client_id: e.target.value })} /></label>
        <label className="text-sm"><span className="text-muted-foreground">Secret reference</span><input className={input} value={(c.secret_path as string) ?? ""} onChange={(e) => setC({ ...c, secret_path: e.target.value })} placeholder="fides/servicenow" /></label>
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
      <label className="text-sm"><span className="text-muted-foreground">Incoming-webhook secret reference</span><input className={input} value={secret} onChange={(e) => setSecret(e.target.value)} placeholder="fides/slack-webhook" /></label>
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
      {key && <pre className="mt-3 rounded-md border border-border bg-background p-3 text-xs text-green-400">Save this key now (shown once):{"\n"}{key}</pre>}
      {list.length > 0 && (
        <table className="mt-4 w-full text-left text-sm font-mono">
          <thead className="text-muted-foreground"><tr><th className="py-1">Name</th><th>Role</th><th>Keys</th><th></th></tr></thead>
          <tbody>{list.map((a) => <tr key={a.id} className="border-t border-border"><td className="py-2">{a.name}</td><td>{a.role}</td><td>{a.active_keys}</td><td><button onClick={() => issue(a.id)} className={ghost}>Issue key</button></td></tr>)}</tbody>
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
          <thead className="text-muted-foreground"><tr><th className="py-1">Name</th><th>Email</th><th>Role</th><th>Set password</th></tr></thead>
          <tbody>{users.map((u) => (
            <tr key={u.id} className="border-t border-border">
              <td className="py-2">{u.name}</td><td className="font-mono text-muted-foreground">{u.email}</td><td>{u.role}</td>
              <td className="flex gap-2 py-2"><input className={input} type="password" placeholder="new password" onChange={(e) => setPw({ ...pw, [u.id]: e.target.value })} /><button onClick={() => setPass(u.id)} className={ghost}>Set</button></td>
            </tr>
          ))}</tbody>
        </table>
      ) : <p className="text-sm text-muted-foreground">No users.</p>}
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
        <h3 className="mb-3 text-xs uppercase tracking-wide text-muted-foreground">Git provider</h3>
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
        <h3 className="mb-3 text-xs uppercase tracking-wide text-muted-foreground">Outbound webhook</h3>
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
  { id: "infra", label: "Infrastructure", el: <InfrastructureTab /> },
  { id: "directory", label: "Directory & Groups", el: <DirectoryTab /> },
  { id: "servicenow", label: "ServiceNow", el: <ServiceNowTab /> },
  { id: "slack", label: "Slack", el: <SlackTab /> },
  { id: "accounts", label: "Service Accounts", el: <ServiceAccountsTab /> },
  { id: "git", label: "Git & Webhooks", el: <GitWebhooksTab /> },
  { id: "users", label: "Users", el: <UsersTab /> },
];

export default function Settings() {
  const [tab, setTab] = useState("infra");
  return (
    <div className="max-w-4xl">
      <h1 className="text-xl font-semibold">Settings</h1>
      <p className="mt-1 text-sm text-muted-foreground">Integrations, credentials, and user management.</p>
      <div className="mt-4 flex gap-1 border-b border-border">
        {TABS.map((t) => (
          <button key={t.id} onClick={() => setTab(t.id)} className={`px-4 py-2 text-sm ${tab === t.id ? "border-b-2 border-primary text-foreground" : "text-muted-foreground"}`}>{t.label}</button>
        ))}
      </div>
      <div className="mt-5">{TABS.find((t) => t.id === tab)?.el}</div>
    </div>
  );
}
