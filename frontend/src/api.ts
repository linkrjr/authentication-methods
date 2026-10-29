// Typed fetch client for the backend HTTP API (see the API contract).
// Same-origin only: Vite proxies /api to the backend, so cookies are first-party.

export type AuthMethod = "password" | "oauth" | "mfa" | "jwt";

export type User = {
  id: string;
  username: string | null;
  displayName: string;
  email: string | null;
  mfaEnabled: boolean;
  createdAt: string;
  lastLoginAt: string | null;
};

export type Me = { user: User; auth: { method: AuthMethod; expiresAt: string } };

export type SecurityEvent = {
  id: string;
  type: string;
  success: boolean;
  ip: string | null;
  userAgent: string | null;
  detail: string | null;
  createdAt: string;
};

export type Issue = { path: string; message: string };

export type MfaLoginResponse =
  | { status: "mfa_required" }
  | { status: "enrollment_required"; qrCodeDataUrl: string; secret: string; otpauthUrl: string };

export type MfaVerifyResponse = { status: "authenticated"; user: User; recoveryCodes?: string[] };

export type TokenResponse = { accessToken: string; tokenType: "Bearer"; expiresIn: number };

export type JwtLoginResponse = TokenResponse & { user: User };

/** Error thrown for any non-2xx response (or network failure, with status 0). */
export class ApiError extends Error {
  readonly status: number;
  /** Machine-readable error code from the response body (e.g. `invalid_credentials`). */
  readonly error: string;
  /** Full parsed error body, including extra fields beyond error/message. */
  readonly body: Readonly<Record<string, unknown>>;

  constructor(status: number, error: string, message: string, body: Record<string, unknown> = {}) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.error = error;
    this.body = body;
  }

  /** Field-level validation issues (`400 validation_failed`). */
  get issues(): Issue[] {
    const issues = this.body.issues;
    if (!Array.isArray(issues)) return [];
    return issues.filter(
      (i): i is Issue =>
        typeof i === "object" && i !== null && typeof i.path === "string" && typeof i.message === "string",
    );
  }

  /** Remaining TOTP attempts (`401 invalid_code`). */
  get attemptsRemaining(): number | undefined {
    const n = this.body.attemptsRemaining;
    return typeof n === "number" ? n : undefined;
  }
}

// ---- CSRF ----------------------------------------------------------------

let csrfToken: string | null = null;
let csrfInFlight: Promise<string> | null = null;

/** Lazily fetches the CSRF token once and caches it in memory; concurrent callers share one request. */
function getCsrfToken(forceRefresh = false): Promise<string> {
  if (forceRefresh) csrfToken = null;
  if (csrfToken) return Promise.resolve(csrfToken);
  csrfInFlight ??= send<{ csrfToken: string }>("/api/auth/csrf", { method: "GET" })
    .then(({ csrfToken: token }) => {
      csrfToken = token;
      return token;
    })
    .finally(() => {
      csrfInFlight = null;
    });
  return csrfInFlight;
}

// ---- Core request --------------------------------------------------------

export type RequestOptions = {
  method?: "GET" | "POST";
  body?: unknown;
  /** Sent as `Authorization: Bearer <token>` when present. */
  accessToken?: string | null;
};

async function send<T>(path: string, opts: RequestOptions, csrf?: string): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (opts.body !== undefined) headers["Content-Type"] = "application/json";
  if (csrf) headers["X-CSRF-Token"] = csrf;
  if (opts.accessToken) headers.Authorization = `Bearer ${opts.accessToken}`;

  let res: Response;
  try {
    res = await fetch(path, {
      method: opts.method ?? "GET",
      headers,
      body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
      credentials: "same-origin",
    });
  } catch {
    throw new ApiError(0, "network_error", "Could not reach the server. Is the backend running?");
  }

  if (res.status === 204) return undefined as T;

  let data: unknown = undefined;
  const text = await res.text();
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = undefined;
    }
  }

  if (!res.ok) {
    // Error bodies follow the contract's `{ error, message, ...extra }` shape; fields are checked individually below.
    const body: Record<string, unknown> =
      typeof data === "object" && data !== null && !Array.isArray(data) ? (data as Record<string, unknown>) : {};
    const error = typeof body.error === "string" ? body.error : "http_error";
    const message =
      typeof body.message === "string"
        ? body.message
        : res.status === 429
          ? "Too many requests. Please wait a moment and try again."
          : `Request failed (HTTP ${res.status}).`;
    throw new ApiError(res.status, error, message, body);
  }

  return data as T;
}

/**
 * Performs an API request. Non-GET requests carry the CSRF token; if the server
 * rejects it (`403 csrf_failed`, e.g. after session rotation) the token is
 * refetched and the request retried exactly once.
 */
export async function apiRequest<T>(path: string, opts: RequestOptions = {}): Promise<T> {
  const method = opts.method ?? "GET";
  if (method === "GET") return send<T>(path, opts);

  try {
    return await send<T>(path, opts, await getCsrfToken());
  } catch (err) {
    if (err instanceof ApiError && err.status === 403 && err.error === "csrf_failed") {
      return send<T>(path, opts, await getCsrfToken(true));
    }
    throw err;
  }
}

// ---- Endpoints -----------------------------------------------------------

export const api = {
  register: (body: { username: string; password: string; displayName?: string }) =>
    apiRequest<{ user: User }>("/api/auth/register", { method: "POST", body }),

  passwordLogin: (body: { username: string; password: string }) =>
    apiRequest<{ user: User }>("/api/auth/password/login", { method: "POST", body }),

  mfaLogin: (body: { username: string; password: string }) =>
    apiRequest<MfaLoginResponse>("/api/auth/mfa/login", { method: "POST", body }),

  mfaVerify: (body: { code: string }) =>
    apiRequest<MfaVerifyResponse>("/api/auth/mfa/verify", { method: "POST", body }),

  jwtLogin: (body: { username: string; password: string }) =>
    apiRequest<JwtLoginResponse>("/api/auth/jwt/login", { method: "POST", body }),

  jwtRefresh: () => apiRequest<TokenResponse>("/api/auth/jwt/refresh", { method: "POST" }),

  jwtLogout: () => apiRequest<void>("/api/auth/jwt/logout", { method: "POST" }),

  logout: () => apiRequest<void>("/api/auth/logout", { method: "POST" }),

  me: (accessToken: string | null) => apiRequest<Me>("/api/me", { accessToken }),

  events: (accessToken: string | null) =>
    apiRequest<{ events: SecurityEvent[] }>("/api/me/events", { accessToken }),

  logoutAll: (accessToken: string | null) =>
    apiRequest<void>("/api/me/logout-all", { method: "POST", accessToken }),

  disableMfa: (accessToken: string | null, body: { code: string }) =>
    apiRequest<void>("/api/me/mfa/disable", { method: "POST", accessToken, body }),
};
