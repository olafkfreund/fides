// Thin client for the same-origin Fides REST API. In production the static
// export is served by the Go server, so requests are same-origin and the
// session cookie is sent automatically. For local dev, set NEXT_PUBLIC_API_BASE
// to the server URL (requires the server to allow CORS with credentials).
const BASE = process.env.NEXT_PUBLIC_API_BASE ?? "";

export class ApiError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.status = status;
  }
}

async function request(
  method: string,
  url: string | URL,
  body?: unknown,
  redirect?: RequestRedirect,
): Promise<Response> {
  const opt: RequestInit = { method, credentials: "include", headers: {}, redirect };
  if (body !== undefined) {
    opt.headers = { "Content-Type": "application/json" };
    opt.body = JSON.stringify(body);
  }
  const res = await fetch(url, opt);
  if (res.status === 401) throw new ApiError("Not signed in", 401);
  if (!res.ok) throw new ApiError(await res.text() || `HTTP ${res.status}`, res.status);
  return res;
}

export async function api<T = unknown>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await request(method, BASE + path, body);
  const text = await res.text();
  try {
    return JSON.parse(text) as T;
  } catch {
    return text as unknown as T;
  }
}

export const apiGet = <T = unknown>(path: string) => api<T>("GET", path);
export const apiPost = <T = unknown>(path: string, body?: unknown) => api<T>("POST", path, body);

export type ListPage<T> = { items: T[]; next: URL | null };

export async function apiListPage<T>(path: string | URL, seen = new Set<string>()): Promise<ListPage<T>> {
  const url = typeof path === "string" ? new URL(BASE + path, window.location.href) : path;
  const base = new URL(BASE || "/", window.location.href);
  if (url.origin !== base.origin || url.protocol !== base.protocol || url.username || url.password) {
    throw new Error("Pagination link points outside the Fides server");
  }
  if (seen.has(url.href)) throw new Error("Repeated pagination link");

  // An unexpected redirect must not send a paginated request to another origin.
  const res = await request("GET", url, undefined, "error");
  const items: unknown = await res.json();
  if (items !== null && !Array.isArray(items)) throw new Error("Expected a list response");

  const target = res.headers.get("Link")?.match(/(?:^|,)\s*<([^>]+)>\s*;\s*rel\s*=\s*(?:"next"|next)(?:\s*[,;]|\s*$)/i)?.[1];
  const next = target ? new URL(target, url) : null;
  if (next) {
    if (next.origin !== base.origin || next.protocol !== base.protocol || next.username || next.password) {
      throw new Error("Pagination link points outside the Fides server");
    }
    next.hash = "";
  }
  seen.add(url.href);
  return { items: (items ?? []) as T[], next };
}

export async function apiList<T = unknown>(path: string): Promise<T[]> {
  const seen = new Set<string>();
  const items: T[] = [];
  let page: string | URL | null = path;
  while (page) {
    const result: ListPage<T> = await apiListPage<T>(page, seen);
    items.push(...result.items);
    page = result.next;
  }
  return items;
}

export async function login(username: string, password: string): Promise<void> {
  await api("POST", "/api/v1/auth/local-login", { username, password });
}
