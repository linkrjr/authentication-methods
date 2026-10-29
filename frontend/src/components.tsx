import { useState, type FormEvent, type ReactNode } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "@tanstack/react-router";
import { ApiError } from "./api";
import { eventsQueryOptions, meQueryOptions } from "./auth";

/** Human-readable message for any thrown value. */
export function errorMessage(err: unknown): string {
  if (err instanceof ApiError) return err.message;
  if (err instanceof Error) return err.message;
  return "Something went wrong.";
}

export function ErrorAlert({ error, children }: { error: unknown; children?: ReactNode }) {
  if (!error) return null;
  return (
    <div className="alert alert-error" role="alert">
      <p>{errorMessage(error)}</p>
      {error instanceof ApiError && error.issues.length > 0 && (
        <ul>
          {error.issues.map((issue, i) => (
            <li key={`${issue.path}-${i}`}>
              {issue.path ? <strong>{issue.path}: </strong> : null}
              {issue.message}
            </li>
          ))}
        </ul>
      )}
      {children}
    </div>
  );
}

/** Error alert with an extra pointer to the MFA login when the account requires it. */
export function LoginError({ error }: { error: unknown }) {
  const needsMfa = error instanceof ApiError && error.status === 403 && error.error === "mfa_required";
  return (
    <ErrorAlert error={error}>
      {needsMfa && (
        <p>
          This account has two-factor authentication enabled.{" "}
          <Link to="/login/mfa">Sign in with MFA instead →</Link>
        </p>
      )}
    </ErrorAlert>
  );
}

export function Notice({ children }: { children: ReactNode }) {
  return (
    <div className="alert alert-info" role="status">
      {children}
    </div>
  );
}

export function Field({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: ReactNode;
  children: ReactNode;
}) {
  return (
    <label className="field">
      <span className="field-label">{label}</span>
      {children}
      {hint ? <span className="field-hint">{hint}</span> : null}
    </label>
  );
}

/** Username + password form shared by the password, MFA (step 1) and JWT views. */
export function CredentialsForm({
  submitLabel,
  pending,
  onSubmit,
}: {
  submitLabel: string;
  pending: boolean;
  onSubmit: (credentials: { username: string; password: string }) => void;
}) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");

  function handleSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    onSubmit({ username, password });
  }

  return (
    <form className="form" onSubmit={handleSubmit}>
      <Field label="Username or email">
        <input
          name="username"
          autoComplete="username"
          autoCapitalize="none"
          spellCheck={false}
          required
          value={username}
          onChange={(e) => setUsername(e.target.value)}
        />
      </Field>
      <Field label="Password">
        <input
          name="password"
          type="password"
          autoComplete="current-password"
          required
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
      </Field>
      <button type="submit" className="btn btn-primary" disabled={pending}>
        {pending ? "Signing in…" : submitLabel}
      </button>
    </form>
  );
}

/** "How this works" + "Security controls" side panel for a login view. */
export function MethodInfo({ steps, controls }: { steps: ReactNode[]; controls: ReactNode[] }) {
  return (
    <aside className="card info-panel">
      <h2>How this works</h2>
      <ol className="steps">
        {steps.map((step, i) => (
          <li key={i}>{step}</li>
        ))}
      </ol>
      <h2>Security controls</h2>
      <ul className="controls">
        {controls.map((control, i) => (
          <li key={i}>{control}</li>
        ))}
      </ul>
    </aside>
  );
}

export function LoginLayout({
  title,
  lead,
  children,
  info,
}: {
  title: string;
  lead: ReactNode;
  children: ReactNode;
  info: ReactNode;
}) {
  return (
    <div className="login-layout">
      <section className="card login-card">
        <p className="eyebrow">
          <Link to="/">← All methods</Link>
        </p>
        <h1>{title}</h1>
        <p className="lead">{lead}</p>
        {children}
      </section>
      {info}
    </div>
  );
}

/**
 * Returns a callback for a successful login: refetches the cached identity (it may belong to a
 * previous session) and goes to the dashboard. Refetching updates the existing query instead of
 * removing it, so subscribers such as the header nav see the new identity.
 */
export function useGoToDashboard() {
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  return async () => {
    queryClient.removeQueries({ queryKey: eventsQueryOptions.queryKey, exact: true });
    // If this fails the dashboard guard redirects home, so the error needs no handling here.
    await queryClient.fetchQuery({ ...meQueryOptions, staleTime: 0 }).catch(() => undefined);
    return navigate({ to: "/dashboard" });
  };
}
