// WebMCP: expose Fides capabilities to browser-integrated AI agents and local
// assistants as callable tools. Uses the native W3C `document.modelContext` API
// where available (Chrome origin trial) and falls back to the @mcp-b/global
// polyfill (navigator.modelContext) elsewhere. Tools run in the page with the
// user's session, so they call the same-origin, cookie-authed Fides API.

import { apiGet, apiPost } from "./api";

type JSONSchema = Record<string, unknown>;
type ToolDef = {
  name: string;
  description: string;
  inputSchema: JSONSchema;
  readOnly: boolean;
  execute: (input: Record<string, unknown>) => Promise<unknown>;
};

// Minimal shape of the modelContext registration surface (native + polyfill).
type ModelContextLike = {
  registerTool: (descriptor: Record<string, unknown>, options?: { signal?: AbortSignal }) => unknown;
};

const q = (params: Record<string, string | number | undefined>) => {
  const sp = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== "") sp.set(k, String(v));
  const s = sp.toString();
  return s ? `?${s}` : "";
};

// The tool catalogue — mirrors the fides-mcp server, over the same-origin API.
const TOOLS: ToolDef[] = [
  {
    name: "fides_list_flows",
    description: "List the configured Fides compliance flows (CI/CD pipelines).",
    inputSchema: { type: "object", properties: {} },
    readOnly: true,
    execute: () => apiGet("/api/v1/flows"),
  },
  {
    name: "fides_list_environments",
    description: "List runtime environments and their compliance status.",
    inputSchema: { type: "object", properties: {} },
    readOnly: true,
    execute: () => apiGet("/api/v1/environments"),
  },
  {
    name: "fides_list_policies",
    description: "List named compliance policies and their jq rules.",
    inputSchema: { type: "object", properties: {} },
    readOnly: true,
    execute: () => apiGet("/api/v1/policies"),
  },
  {
    name: "fides_controls_coverage",
    description: "Get each governance control's coverage across environments.",
    inputSchema: { type: "object", properties: {} },
    readOnly: true,
    execute: () => apiGet("/api/v1/controls/coverage"),
  },
  {
    name: "fides_search_artifacts",
    description: "Search build artifacts by SHA256 prefix and/or name.",
    inputSchema: { type: "object", properties: { sha: { type: "string" }, name: { type: "string" } } },
    readOnly: true,
    execute: (i) => apiGet(`/api/v1/search/artifacts${q({ sha: i.sha as string, name: i.name as string })}`),
  },
  {
    name: "fides_search_attestations",
    description: "Search attestations by type, compliance (true/false), or artifact SHA256.",
    inputSchema: { type: "object", properties: { type: { type: "string" }, compliant: { type: "string", enum: ["", "true", "false"] }, sha: { type: "string" } } },
    readOnly: true,
    execute: (i) => apiGet(`/api/v1/search/attestations${q({ type: i.type as string, compliant: i.compliant as string, sha: i.sha as string })}`),
  },
  {
    name: "fides_deployment_frequency",
    description: "Weekly deployment frequency per environment (DORA metric).",
    inputSchema: { type: "object", properties: { weeks: { type: "number" } } },
    readOnly: true,
    execute: (i) => apiGet(`/api/v1/metrics/deployment-frequency${q({ weeks: (i.weeks as number) || 12 })}`),
  },
  {
    name: "fides_compliance_summary",
    description: "Overall DORA/compliance summary (deployments, compliance rate, change-failure rate).",
    inputSchema: { type: "object", properties: { days: { type: "number" } } },
    readOnly: true,
    execute: (i) => apiGet(`/api/v1/metrics/dora${q({ days: (i.days as number) || 30 })}`),
  },
  // --- safe actions (not read-only) ---
  {
    name: "fides_enforce_control",
    description: "Enforce a control by creating an enabled environment policy requiring its evidence types. Provide a control key and either an environment_id or all=true.",
    inputSchema: {
      type: "object",
      properties: { control: { type: "string" }, environment_id: { type: "string" }, all: { type: "boolean" } },
      required: ["control"],
    },
    readOnly: false,
    execute: (i) => {
      const body = i.all ? { all: true } : { environment_id: i.environment_id };
      return apiPost(`/api/v1/controls/${encodeURIComponent(String(i.control))}/enforce`, body);
    },
  },
  {
    name: "fides_import_framework",
    description: "Import a regulated framework's control catalogue (SOC2, ISO27001, NIST-800-53, PCI-DSS, DORA, PSD2, SOX). Idempotent.",
    inputSchema: { type: "object", properties: { framework: { type: "string" } }, required: ["framework"] },
    readOnly: false,
    execute: (i) => apiPost("/api/v1/controls/import-framework", { framework: i.framework }),
  },
];

let registered = false;

/** Register Fides tools with the browser's WebMCP surface. Safe to call once on
 *  the client; no-ops if no modelContext is available and the polyfill fails. */
export async function registerFidesWebMCP(): Promise<void> {
  if (registered || typeof window === "undefined") return;
  registered = true;

  // Prefer the native spec surface (document.modelContext); otherwise load the
  // polyfill which installs navigator.modelContext + a browser transport.
  let mc: ModelContextLike | undefined = (document as unknown as { modelContext?: ModelContextLike }).modelContext;
  let useExecuteKey = true; // native spec uses `execute`
  if (!mc?.registerTool) {
    try {
      await import("@mcp-b/global"); // polyfill side-effect
    } catch {
      return; // no WebMCP available in this browser
    }
    mc = (navigator as unknown as { modelContext?: ModelContextLike }).modelContext
      || (document as unknown as { modelContext?: ModelContextLike }).modelContext;
    useExecuteKey = false; // polyfill uses `handler`
  }
  if (!mc?.registerTool) return;

  for (const t of TOOLS) {
    const descriptor: Record<string, unknown> = {
      name: t.name,
      description: t.description,
      inputSchema: t.inputSchema,
      annotations: { readOnlyHint: t.readOnly },
      // Provide both callback keys so either surface works.
      [useExecuteKey ? "execute" : "handler"]: t.execute,
      [useExecuteKey ? "handler" : "execute"]: t.execute,
    };
    try {
      await mc.registerTool(descriptor);
    } catch {
      // ignore individual tool registration failures
    }
  }
}
