import { useEffect, useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient, useSuspenseQuery } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import type { AuthMethod, User } from "../api";
import {
  disableMfa,
  eventsQueryOptions,
  getAccessToken,
  logout,
  logoutAll,
  meQueryOptions,
} from "../auth";
import { ErrorAlert, Field } from "../components";

const METHOD_LABELS: Record<AuthMethod, string> = {
  password: "Password",
  oauth: "OAuth 2.0",
  mfa: "MFA (TOTP)",
  jwt: "JWT",
};

function formatDate(iso: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
}

export function DashboardPage() {
  const { data: me } = useSuspenseQuery(meQueryOptions);
  const queryClient = useQueryClient();
  const navigate = useNavigate();

  const signOut = useMutation({
    mutationFn: (everywhere: boolean) => (everywhere ? logoutAll() : logout(me.auth.method)),
    onSuccess: async () => {
      // Leave the dashboard first so its queries don't immediately refetch the cleared identity.
      await navigate({ to: "/" });
      queryClient.clear();
    },
  });

  const { user, auth } = me;

  return (
    <div className="stack">
      <section className="card dashboard-hero">
        <div>
          <p className="eyebrow">Signed in</p>
          <h1>Hello, {user.displayName}!</h1>
          <p className="muted">
            Signed in with <span className={`badge badge-${auth.method}`}>{METHOD_LABELS[auth.method]}</span>
          </p>
          <ExpiryLine method={auth.method} expiresAt={auth.expiresAt} />
        </div>
        <div className="button-row">
          <button
            type="button"
            className="btn"
            disabled={signOut.isPending}
            onClick={() => signOut.mutate(false)}
          >
            Sign out
          </button>
          <button
            type="button"
            className="btn btn-danger"
            disabled={signOut.isPending}
            onClick={() => signOut.mutate(true)}
          >
            Sign out everywhere
          </button>
        </div>
        <ErrorAlert error={signOut.error} />
      </section>

      <div className="dashboard-grid">
        <section className="card">
          <h2>Your account</h2>
          <UserTable user={user} />
        </section>

        <section className="card">
          <h2>Two-factor authentication</h2>
          {user.username === null ? (
            <p className="muted">This account signs in through the identity provider, which owns its second factor.</p>
          ) : (
            <MfaStatus enabled={user.mfaEnabled} />
          )}
        </section>
      </div>

      {auth.method === "jwt" ? <JwtPanel /> : null}

      <section className="card">
        <h2>Recent security events</h2>
        <EventsTable />
      </section>
    </div>
  );
}

function ExpiryLine({ method, expiresAt }: { method: AuthMethod; expiresAt: string }) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const id = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(id);
  }, []);

  const expiry = new Date(expiresAt).getTime();
  const seconds = Math.max(0, Math.round((expiry - now) / 1000));
  const remaining =
    seconds >= 3600
      ? `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`
      : `${Math.floor(seconds / 60)}m ${String(seconds % 60).padStart(2, "0")}s`;

  return (
    <p className="muted small">
      {method === "jwt" ? "Access token expires" : "Session expires"} {formatDate(expiresAt)}{" "}
      {Number.isNaN(expiry) ? null : seconds > 0 ? `(in ${remaining})` : "(expired)"}
      {method === "jwt" ? " — it is refreshed automatically via the refresh cookie when needed." : null}
    </p>
  );
}

function UserTable({ user }: { user: User }) {
  const rows: [string, string][] = [
    ["User ID", user.id],
    ["Username", user.username ?? "— (OAuth account)"],
    ["Display name", user.displayName],
    ["Email", user.email ?? "—"],
    ["MFA enabled", user.mfaEnabled ? "Yes" : "No"],
    ["Created", formatDate(user.createdAt)],
    ["Last login", formatDate(user.lastLoginAt)],
  ];
  return (
    <table className="kv-table">
      <tbody>
        {rows.map(([k, v]) => (
          <tr key={k}>
            <th scope="row">{k}</th>
            <td>{v}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function MfaStatus({ enabled }: { enabled: boolean }) {
  const queryClient = useQueryClient();
  const [code, setCode] = useState("");
  const disable = useMutation({
    mutationFn: disableMfa,
    onSuccess: async () => {
      setCode("");
      await queryClient.invalidateQueries({ queryKey: ["me"] }); // also refreshes the events list
    },
  });

  if (!enabled) {
    return (
      <p className="muted">
        {disable.isSuccess ? "MFA has been disabled. " : "MFA is not enabled. "}
        Sign in through the MFA login to enroll an authenticator app.
      </p>
    );
  }

  function handleSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    disable.mutate(code);
  }

  return (
    <div className="stack">
      <p>
        <span className="status-dot status-on" aria-hidden="true" /> MFA is <strong>enabled</strong> for this account.
      </p>
      <form className="form inline-form" onSubmit={handleSubmit}>
        <Field label="Current code to disable MFA">
          <input
            name="code"
            autoComplete="one-time-code"
            inputMode="numeric"
            pattern="[0-9]{6}"
            maxLength={6}
            placeholder="123456"
            className="mono code-input"
            required
            value={code}
            onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
          />
        </Field>
        <button type="submit" className="btn btn-danger" disabled={disable.isPending}>
          {disable.isPending ? "Disabling…" : "Disable MFA"}
        </button>
      </form>
      <ErrorAlert error={disable.error} />
    </div>
  );
}

/** Decodes one base64url JWT segment to pretty-printed JSON (no verification). */
function decodeSegment(segment: string | undefined): string {
  if (!segment) return "(missing)";
  try {
    const base64 = segment.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(segment.length / 4) * 4, "=");
    const bytes = Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
    return JSON.stringify(JSON.parse(new TextDecoder().decode(bytes)), null, 2);
  } catch {
    return "(could not decode)";
  }
}

function JwtPanel() {
  // Re-render together with the `me` query: a refresh may have replaced the token.
  const token = getAccessToken();
  if (!token) {
    return (
      <section className="card">
        <h2>Access token</h2>
        <p className="muted">No access token in memory.</p>
      </section>
    );
  }
  const [header, payload] = token.split(".");

  return (
    <section className="card">
      <h2>Access token (in memory)</h2>
      <p className="alert alert-warn">
        Decoded client-side, <strong>not verified</strong> — the server verifies the signature. Anyone can read a JWT's
        contents; never put secrets in it.
      </p>
      <div className="jwt-grid">
        <div>
          <h3>Header</h3>
          <pre className="code-block">{decodeSegment(header)}</pre>
        </div>
        <div>
          <h3>Payload</h3>
          <pre className="code-block">{decodeSegment(payload)}</pre>
        </div>
      </div>
    </section>
  );
}

function EventsTable() {
  const { data: events, error, isPending } = useQuery(eventsQueryOptions);

  if (isPending) return <p className="muted">Loading events…</p>;
  if (error) return <ErrorAlert error={error} />;
  if (events.length === 0) return <p className="muted">No events yet.</p>;

  return (
    <div className="table-scroll">
      <table className="data-table">
        <thead>
          <tr>
            <th scope="col">Time</th>
            <th scope="col">Event</th>
            <th scope="col">Result</th>
            <th scope="col">IP</th>
            <th scope="col">Detail</th>
            <th scope="col">User agent</th>
          </tr>
        </thead>
        <tbody>
          {events.map((ev) => (
            <tr key={ev.id}>
              <td className="nowrap">{formatDate(ev.createdAt)}</td>
              <td>
                <code>{ev.type}</code>
              </td>
              <td>
                <span className={ev.success ? "pill pill-ok" : "pill pill-fail"}>{ev.success ? "success" : "failure"}</span>
              </td>
              <td className="mono">{ev.ip ?? "—"}</td>
              <td>{ev.detail ?? "—"}</td>
              <td className="truncate" title={ev.userAgent ?? undefined}>
                {ev.userAgent ?? "—"}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
