import { queryOptions } from "@tanstack/react-query";
import { api, ApiError, type AuthMethod, type Me, type SecurityEvent } from "./api";

// The JWT access token lives ONLY in this module-level variable — never in
// localStorage/sessionStorage. Web storage is readable by any script running on
// the page, so a single XSS bug would let an attacker exfiltrate the token and
// replay it from anywhere until it expires. Keeping it in memory limits the
// blast radius to the lifetime of this tab; after a reload we silently obtain a
// new one via the httpOnly refresh cookie, which scripts cannot read.
let accessToken: string | null = null;

export function getAccessToken(): string | null {
  return accessToken;
}

function setAccessToken(token: string | null): void {
  accessToken = token;
}

// ---- Token refresh -------------------------------------------------------

let refreshInFlight: Promise<boolean> | null = null;

/**
 * Exchanges the httpOnly refresh cookie for a new access token. Concurrent
 * callers share one request: refresh tokens rotate and reuse is detected, so
 * two parallel refreshes would look like token theft to the server.
 */
function refreshAccessToken(): Promise<boolean> {
  refreshInFlight ??= api
    .jwtRefresh()
    .then(({ accessToken: token }) => {
      setAccessToken(token);
      return true;
    })
    .catch((err: unknown) => {
      if (err instanceof ApiError && err.status === 401) {
        setAccessToken(null);
        return false;
      }
      throw err;
    })
    .finally(() => {
      refreshInFlight = null;
    });
  return refreshInFlight;
}

/** A 401 that means "not authenticated" (as opposed to e.g. a wrong TOTP code). */
function isAuthFailure(err: unknown): err is ApiError {
  return err instanceof ApiError && err.status === 401 && err.error !== "invalid_code";
}

/**
 * Runs an authenticated call. With an in-memory access token it is sent as a
 * Bearer token; otherwise the cookie session is used. On a 401 we try one
 * refresh (a refresh cookie may survive a page reload) and retry with the new
 * bearer token; if that fails the original 401 is rethrown.
 */
async function withAuth<T>(call: (token: string | null) => Promise<T>): Promise<T> {
  try {
    return await call(accessToken);
  } catch (err) {
    if (!isAuthFailure(err)) throw err;
    if (accessToken) setAccessToken(null);
    if (await refreshAccessToken()) return call(accessToken);
    throw err;
  }
}

// ---- Public API ----------------------------------------------------------

export function fetchMe(): Promise<Me> {
  return withAuth((token) => api.me(token));
}

export async function fetchEvents(): Promise<SecurityEvent[]> {
  const { events } = await withAuth((token) => api.events(token));
  return events;
}

export function disableMfa(code: string): Promise<void> {
  return withAuth((token) => api.disableMfa(token, { code }));
}

export async function loginJwt(username: string, password: string): Promise<void> {
  const { accessToken: token } = await api.jwtLogin({ username, password });
  setAccessToken(token);
}

export async function logout(method: AuthMethod): Promise<void> {
  if (method === "jwt") {
    try {
      await api.jwtLogout();
    } finally {
      setAccessToken(null);
    }
  } else {
    await api.logout();
  }
}

export async function logoutAll(): Promise<void> {
  try {
    await withAuth((token) => api.logoutAll(token));
  } finally {
    setAccessToken(null);
  }
}

// ---- Queries -------------------------------------------------------------

export const meQueryOptions = queryOptions({
  queryKey: ["me"],
  queryFn: fetchMe,
  retry: false,
  staleTime: 30_000,
});

export const eventsQueryOptions = queryOptions({
  queryKey: ["me", "events"],
  queryFn: fetchEvents,
  retry: false,
});
