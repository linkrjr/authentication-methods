import { useEffect, useState } from "react";
import { useSearch } from "@tanstack/react-router";
import { ErrorAlert, LoginLayout, MethodInfo } from "../components";

const OAUTH_ERRORS: Record<string, string> = {
  access_denied: "You declined the request at the identity provider, so you were not signed in.",
  invalid_state:
    "The sign-in response could not be matched to this browser (state check failed or expired). Please start again.",
  oauth_failed: "The identity provider sign-in could not be completed. Please try again.",
};
const GENERIC_OAUTH_ERROR = "Sign-in with the identity provider failed. Please try again.";

export function LoginOAuthPage() {
  const { error } = useSearch({ from: "/login/oauth" });
  // `error` is untrusted URL input: only known codes map to specific text; anything else gets a generic message.
  const errorText = error
    ? ((Object.hasOwn(OAUTH_ERRORS, error) ? OAUTH_ERRORS[error] : undefined) ?? GENERIC_OAUTH_ERROR)
    : null;
  const [redirecting, setRedirecting] = useState(false);

  // Coming back via the browser's Back button may restore this page from the
  // back/forward cache with the button still disabled; re-enable it.
  useEffect(() => {
    const onPageShow = (e: PageTransitionEvent) => {
      if (e.persisted) setRedirecting(false);
    };
    window.addEventListener("pageshow", onPageShow);
    return () => window.removeEventListener("pageshow", onPageShow);
  }, []);

  function start() {
    setRedirecting(true);
    // Full-page navigation (not fetch): the backend answers with a 302 to the IdP.
    window.location.assign("/api/auth/oauth/demo/start");
  }

  return (
    <LoginLayout
      title="OAuth 2.0 login"
      lead="Sign in through an external identity provider (a local mock IdP). This app never sees your IdP password."
      info={
        <MethodInfo
          steps={[
            "The backend generates a random state and a PKCE code verifier (kept server-side), binds the state to your browser with an httpOnly cookie, and redirects you to the IdP with the S256 code challenge.",
            "You sign in and consent at the identity provider.",
            "The IdP redirects back to the registered redirect URI with a one-time authorization code and the state.",
            "The backend checks the state against its cookie, then exchanges the code plus the PKCE verifier for the user's identity.",
            "A session is created and you land on the dashboard.",
          ]}
          controls={[
            "Authorization code flow with PKCE (S256)",
            "state parameter bound to an httpOnly cookie (login CSRF protection)",
            "Exact redirect_uri matching at the IdP",
            "Single-use, short-lived authorization codes",
            "No automatic account linking by email — OAuth identities get their own account",
            "Session cookie is httpOnly + SameSite, rotated on login",
          ]}
        />
      }
    >
      {errorText ? <ErrorAlert error={new Error(errorText)} /> : null}
      <button type="button" className="btn btn-primary btn-block" onClick={start} disabled={redirecting}>
        {redirecting ? "Redirecting to the identity provider…" : "Continue with Demo IdP"}
      </button>
      <p className="muted small">You'll be redirected to the identity provider and then back to the dashboard.</p>
    </LoginLayout>
  );
}
