import { Link } from "@tanstack/react-router";

type MethodCard = {
  to: "/login/password" | "/login/oauth" | "/login/mfa" | "/login/jwt";
  title: string;
  tag: string;
  description: string;
};

const methods: MethodCard[] = [
  {
    to: "/login/password",
    title: "Password",
    tag: "Session cookie",
    description:
      "Classic username + password. The server verifies an argon2id hash and issues an httpOnly session cookie.",
  },
  {
    to: "/login/oauth",
    title: "OAuth 2.0",
    tag: "Auth code + PKCE",
    description:
      "Delegate sign-in to an identity provider (a local mock IdP) using the authorization code flow with PKCE.",
  },
  {
    to: "/login/mfa",
    title: "MFA (TOTP)",
    tag: "Something you have",
    description:
      "Password plus a 6-digit time-based code from an authenticator app. First sign-in walks you through enrollment.",
  },
  {
    to: "/login/jwt",
    title: "JWT",
    tag: "Access + refresh tokens",
    description:
      "A short-lived signed access token held in memory, renewed with a rotating refresh token in an httpOnly cookie.",
  },
];

export function HomePage() {
  return (
    <div className="stack">
      <section className="hero">
        <h1>Four ways to sign in</h1>
        <p className="lead">
          Each card below opens its own login view that explains the flow and the security controls behind it. Every
          successful login lands on the same dashboard.
        </p>
      </section>

      <div className="card-grid">
        {methods.map((m) => (
          <Link key={m.to} to={m.to} className="card method-card">
            <span className="badge">{m.tag}</span>
            <h2>{m.title}</h2>
            <p>{m.description}</p>
            <span className="card-cta">Sign in with {m.title} →</span>
          </Link>
        ))}
      </div>

      <section className="card callout">
        <div>
          <h2>Need an account?</h2>
          <p>
            Password, MFA and JWT logins share the same accounts, created via registration. OAuth creates its own
            account through the identity provider — accounts are never linked automatically by email.
          </p>
        </div>
        <Link to="/register" className="btn btn-primary">
          Create an account
        </Link>
      </section>
    </div>
  );
}
