import { useMutation } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { loginJwt } from "../auth";
import { CredentialsForm, LoginError, LoginLayout, MethodInfo, useGoToDashboard } from "../components";

export function LoginJwtPage() {
  const goToDashboard = useGoToDashboard();
  const login = useMutation({
    mutationFn: ({ username, password }: { username: string; password: string }) => loginJwt(username, password),
    onSuccess: () => goToDashboard(),
  });

  return (
    <LoginLayout
      title="JWT login"
      lead="Sign in to receive a short-lived signed access token (kept in memory) and a rotating refresh token (kept in an httpOnly cookie)."
      info={
        <MethodInfo
          steps={[
            "You submit your username and password; the server verifies them like the password login.",
            "The server returns a short-lived HS256 access token and sets a refresh token in an httpOnly cookie.",
            "The app keeps the access token in memory and sends it as an Authorization: Bearer header.",
            "When it expires (or after a reload) the app exchanges the refresh cookie for a new pair; the old refresh token is retired.",
          ]}
          controls={[
            "Short-lived HS256 access token held in memory only — never in localStorage",
            "Algorithm, issuer and audience pinned when verifying tokens",
            "Rotating refresh token in an httpOnly, SameSite=Strict cookie scoped to /api/auth/jwt",
            "Refresh token reuse detection revokes the whole token family",
            "Token versioning so “sign out everywhere” invalidates outstanding access tokens",
            "Generic errors, account lockout and rate limiting on login",
          ]}
        />
      }
    >
      <CredentialsForm submitLabel="Get tokens" pending={login.isPending} onSubmit={(c) => login.mutate(c)} />
      <LoginError error={login.error} />
      <p className="muted small">
        No account yet? <Link to="/register">Register</Link>
      </p>
    </LoginLayout>
  );
}
