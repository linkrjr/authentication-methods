import { useState, type FormEvent } from "react";
import { useMutation } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { api } from "../api";
import { ErrorAlert, Field } from "../components";

const MIN_PASSWORD = 12;
const MAX_PASSWORD = 128;

export function RegisterPage() {
  const [username, setUsername] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [clientError, setClientError] = useState<string | null>(null);

  const register = useMutation({ mutationFn: api.register });

  function handleSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    // Client-side checks are a convenience only; the server is authoritative.
    if (password.length < MIN_PASSWORD || password.length > MAX_PASSWORD) {
      setClientError(`Password must be ${MIN_PASSWORD}–${MAX_PASSWORD} characters.`);
      return;
    }
    if (password !== confirm) {
      setClientError("Passwords do not match.");
      return;
    }
    setClientError(null);
    const trimmedName = displayName.trim();
    register.mutate({ username, password, ...(trimmedName ? { displayName: trimmedName } : {}) });
  }

  if (register.isSuccess) {
    const { user } = register.data;
    return (
      <section className="card narrow">
        <h1>Account created</h1>
        <p className="lead">
          Welcome, <strong>{user.displayName}</strong>. Your account <code>{user.username}</code> works with the
          password, MFA and JWT logins:
        </p>
        <div className="button-row">
          <Link to="/login/password" className="btn btn-primary">
            Password login
          </Link>
          <Link to="/login/mfa" className="btn">
            MFA login
          </Link>
          <Link to="/login/jwt" className="btn">
            JWT login
          </Link>
        </div>
      </section>
    );
  }

  return (
    <section className="card narrow">
      <p className="eyebrow">
        <Link to="/">← All methods</Link>
      </p>
      <h1>Create an account</h1>
      <p className="lead">Used by the password, MFA and JWT logins. OAuth accounts are created via the IdP.</p>

      <form className="form" onSubmit={handleSubmit}>
        <Field label="Username or email" hint="3–32 letters, digits, _ . - — or an email address">
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
        <Field label="Display name (optional)">
          <input
            name="displayName"
            autoComplete="nickname"
            value={displayName}
            onChange={(e) => setDisplayName(e.target.value)}
          />
        </Field>
        <Field label="Password" hint={`${MIN_PASSWORD}–${MAX_PASSWORD} characters. A long passphrase is best.`}>
          <input
            name="password"
            type="password"
            autoComplete="new-password"
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </Field>
        <Field label="Confirm password">
          <input
            name="confirmPassword"
            type="password"
            autoComplete="new-password"
            required
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
          />
        </Field>

        {clientError ? (
          <div className="alert alert-error" role="alert">
            <p>{clientError}</p>
          </div>
        ) : (
          <ErrorAlert error={register.error} />
        )}

        <button type="submit" className="btn btn-primary" disabled={register.isPending}>
          {register.isPending ? "Creating account…" : "Create account"}
        </button>
      </form>
    </section>
  );
}
