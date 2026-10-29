import { useMutation } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { api } from "../api";
import { CredentialsForm, LoginError, LoginLayout, MethodInfo, useGoToDashboard } from "../components";

export function LoginPasswordPage() {
  const goToDashboard = useGoToDashboard();
  const login = useMutation({
    mutationFn: api.passwordLogin,
    onSuccess: () => goToDashboard(),
  });

  return (
    <LoginLayout
      title="Password login"
      lead="Sign in with a username and password. The server keeps your session; the browser only holds an opaque cookie."
      info={
        <MethodInfo
          steps={[
            "The browser sends your username and password over HTTPS with a CSRF token.",
            "The server looks up the account and verifies the password against its argon2id hash.",
            "On success the old session ID is discarded and a fresh one is issued (session rotation).",
            "The session ID is stored in an httpOnly cookie; every later request is identified by it.",
          ]}
          controls={[
            "argon2id password hashing with a per-password random salt plus a server-side pepper",
            "Generic “invalid username or password” errors — no account enumeration",
            "Account lockout after repeated failures",
            "Rate limiting on login attempts",
            "Session fixation protection: session ID rotated on login",
            "HttpOnly + SameSite session cookies (not readable by JavaScript)",
            "CSRF tokens required on every state-changing request",
          ]}
        />
      }
    >
      <CredentialsForm submitLabel="Sign in" pending={login.isPending} onSubmit={(c) => login.mutate(c)} />
      <LoginError error={login.error} />
      <p className="muted small">
        No account yet? <Link to="/register">Register</Link>
      </p>
    </LoginLayout>
  );
}
