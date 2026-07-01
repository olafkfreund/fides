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

export async function api<T = unknown>(
  method: string,
  path: string,
  body?: unknown,
): Promise<T> {
  const opt: RequestInit = { method, credentials: "include", headers: {} };
  if (body !== undefined) {
    opt.headers = { "Content-Type": "application/json" };
    opt.body = JSON.stringify(body);
  }
  const res = await fetch(BASE + path, opt);
  const text = await res.text();
  if (res.status === 401) throw new ApiError("Not signed in", 401);
  if (!res.ok) throw new ApiError(text || `HTTP ${res.status}`, res.status);
  try {
    return JSON.parse(text) as T;
  } catch {
    return text as unknown as T;
  }
}

export const apiGet = <T = unknown>(path: string) => api<T>("GET", path);
export const apiPost = <T = unknown>(path: string, body?: unknown) => api<T>("POST", path, body);

export async function login(username: string, password: string): Promise<void> {
  await api("POST", "/api/v1/auth/local-login", { username, password });
}
