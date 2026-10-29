import { createHash } from "node:crypto";
import express, { type Request, type Response } from "express";
import helmet from "helmet";
import { config } from "../config";
import { randomToken, safeEqual } from "../security/crypto";

/**
 * "DemoID": a deliberately small OAuth 2.0 authorization server so the OAuth login works
 * without third-party credentials. It still enforces what a real provider must:
 * registered clients, exact redirect_uri matching, mandatory PKCE S256, short-lived single-use
 * authorization codes, client authentication, and code-replay revocation.
 * Its state is in memory; restarting it simply invalidates in-flight logins.
 */

interface Identity {
  sub: string;
  name: string;
  email: string;
}

const IDENTITIES: Identity[] = [
  { sub: "demoid|1001", name: "Ada Lovelace", email: "ada@demoid.test" },
  { sub: "demoid|1002", name: "Alan Turing", email: "alan@demoid.test" },
];

interface AuthorizationRequest {
  clientId: string;
  redirectUri: string;
  state: string;
  scope: string;
  codeChallenge: string;
  expiresAt: number;
}

interface IssuedCode extends Omit<AuthorizationRequest, "state"> {
  sub: string;
}

const TRANSACTION_TTL_MS = 5 * 60 * 1000;
const CODE_TTL_MS = 60 * 1000;
const ACCESS_TOKEN_TTL_MS = 5 * 60 * 1000;

const PAGE_STYLE = `
  body{font-family:system-ui,sans-serif;background:#0f172a;color:#e2e8f0;display:grid;place-items:center;min-height:100vh;margin:0}
  main{background:#1e293b;padding:2rem;border-radius:12px;width:min(420px,90vw);box-shadow:0 10px 30px #0008}
  h1{margin:0 0 .25rem;font-size:1.4rem}.muted{color:#94a3b8;font-size:.9rem}
  label{display:flex;gap:.75rem;align-items:center;padding:.75rem;border:1px solid #334155;border-radius:8px;margin:.5rem 0;cursor:pointer}
  .actions{display:flex;gap:.5rem;margin-top:1rem}button{flex:1;padding:.65rem;border-radius:8px;border:0;font-weight:600;cursor:pointer}
  .allow{background:#22c55e;color:#052e16}.deny{background:#334155;color:#e2e8f0}
`;

const escapeHtml = (value: string) =>
  value.replace(/[&<>"']/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[ch]!);

export function createOAuthProvider() {
  const clients = new Map([
    [config.oauth.clientId, { secret: config.oauth.clientSecret, name: "Auth Patterns Demo", redirectUris: [config.oauth.redirectUri as string] }],
  ]);
  const transactions = new Map<string, AuthorizationRequest>();
  const codes = new Map<string, IssuedCode>();
  const usedCodes = new Map<string, { accessTokens: string[]; expiresAt: number }>();
  const accessTokens = new Map<string, { sub: string; expiresAt: number }>();

  const sweep = setInterval(() => {
    const now = Date.now();
    for (const store of [transactions, codes, usedCodes, accessTokens] as Map<string, { expiresAt: number }>[]) {
      for (const [key, value] of store) if (value.expiresAt <= now) store.delete(key);
    }
  }, 60_000);
  sweep.unref();

  const app = express();
  app.disable("x-powered-by");
  // CSP is set per page below. Referrer-Policy "same-origin" keeps a real Origin header on the consent POST.
  app.use(helmet({ contentSecurityPolicy: false, referrerPolicy: { policy: "same-origin" } }));
  app.use(express.urlencoded({ extended: false, limit: "5kb" }));

  function renderError(res: Response, message: string) {
    res.status(400).type("html").send(`<!doctype html><title>DemoID</title><style>${PAGE_STYLE}</style><main><h1>DemoID</h1><p>${escapeHtml(message)}</p></main>`);
  }

  function redirectWithError(res: Response, redirectUri: string, state: string, error: string) {
    const url = new URL(redirectUri);
    url.searchParams.set("error", error);
    url.searchParams.set("state", state);
    res.redirect(303, url.toString());
  }

  app.get("/authorize", (req: Request, res: Response) => {
    const q = req.query as Record<string, unknown>;
    const client = typeof q.client_id === "string" ? clients.get(q.client_id) : undefined;
    // An unknown client or unregistered redirect_uri must NOT be redirected to (open redirect / code theft).
    if (!client || typeof q.redirect_uri !== "string" || !client.redirectUris.includes(q.redirect_uri)) {
      return renderError(res, "Unknown client or unregistered redirect_uri.");
    }
    const state = typeof q.state === "string" ? q.state : "";
    if (q.response_type !== "code") return redirectWithError(res, q.redirect_uri, state, "unsupported_response_type");
    if (!state || state.length > 256) return redirectWithError(res, q.redirect_uri, state, "invalid_request");
    if (q.code_challenge_method !== "S256" || typeof q.code_challenge !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(q.code_challenge)) {
      return redirectWithError(res, q.redirect_uri, state, "invalid_request");
    }

    const transactionId = randomToken();
    transactions.set(transactionId, {
      clientId: q.client_id as string,
      redirectUri: q.redirect_uri,
      state,
      scope: typeof q.scope === "string" ? q.scope.slice(0, 200) : "",
      codeChallenge: q.code_challenge,
      expiresAt: Date.now() + TRANSACTION_TTL_MS,
    });

    const nonce = randomToken(16);
    res.set(
      "Content-Security-Policy",
      // form-action must allow the client origin too: browsers apply it to the post-submit redirect.
      `default-src 'none'; style-src 'nonce-${nonce}'; form-action 'self' ${new URL(q.redirect_uri).origin}; frame-ancestors 'none'; base-uri 'none'`,
    );
    res.set("Cache-Control", "no-store");
    const options = IDENTITIES.map(
      (identity, index) => `<label><input type="radio" name="sub" value="${escapeHtml(identity.sub)}" ${index === 0 ? "checked" : ""}>
        <span><strong>${escapeHtml(identity.name)}</strong><br><span class="muted">${escapeHtml(identity.email)}</span></span></label>`,
    ).join("");
    res.type("html").send(`<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Sign in with DemoID</title>
      <meta name="viewport" content="width=device-width,initial-scale=1"><style nonce="${nonce}">${PAGE_STYLE}</style></head>
      <body><main><h1>DemoID</h1><p class="muted">Mock identity provider · port ${config.oauth.providerPort}</p>
      <p><strong>${escapeHtml(client.name)}</strong> wants to access your profile and e-mail address.</p>
      <form method="post" action="/authorize"><input type="hidden" name="transaction" value="${transactionId}">
      <p class="muted">Continue as:</p>${options}
      <div class="actions"><button class="deny" name="decision" value="deny">Deny</button>
      <button class="allow" name="decision" value="allow">Allow</button></div></form></main></body></html>`);
  });

  app.post("/authorize", (req: Request, res: Response) => {
    // The consent form posts to itself; reject cross-site submissions (consent CSRF).
    const origin = req.get("origin");
    if (origin && origin !== config.oauth.providerUrl) return renderError(res, "Cross-origin request rejected.");
    const transactionId = typeof req.body?.transaction === "string" ? req.body.transaction : "";
    const transaction = transactions.get(transactionId);
    transactions.delete(transactionId);
    if (!transaction || transaction.expiresAt <= Date.now()) return renderError(res, "This sign-in request expired. Start again.");
    if (req.body.decision !== "allow") return redirectWithError(res, transaction.redirectUri, transaction.state, "access_denied");
    const identity = IDENTITIES.find((candidate) => candidate.sub === req.body.sub);
    if (!identity) return renderError(res, "Unknown identity.");

    const code = randomToken();
    codes.set(code, {
      clientId: transaction.clientId,
      redirectUri: transaction.redirectUri,
      scope: transaction.scope,
      codeChallenge: transaction.codeChallenge,
      sub: identity.sub,
      expiresAt: Date.now() + CODE_TTL_MS,
    });
    const url = new URL(transaction.redirectUri);
    url.searchParams.set("code", code);
    url.searchParams.set("state", transaction.state);
    res.redirect(303, url.toString());
  });

  app.post("/token", (req: Request, res: Response) => {
    res.set("Cache-Control", "no-store");
    const fail = (status: number, error: string) => res.status(status).json({ error });

    // client_secret_basic authentication, compared in constant time.
    const [scheme, encoded] = (req.get("authorization") ?? "").split(" ");
    const [rawId = "", rawSecret = ""] = scheme === "Basic" && encoded ? Buffer.from(encoded, "base64").toString().split(":") : [];
    let clientId = "";
    let clientSecret = "";
    try {
      clientId = decodeURIComponent(rawId);
      clientSecret = decodeURIComponent(rawSecret);
    } catch {
      return fail(401, "invalid_client");
    }
    const client = clients.get(clientId);
    if (!client || !clientSecret || !safeEqual(clientSecret, client.secret)) return fail(401, "invalid_client");

    if (req.body?.grant_type !== "authorization_code") return fail(400, "unsupported_grant_type");
    const code = typeof req.body.code === "string" ? req.body.code : "";

    // RFC 6749 §4.1.2: a replayed code means it leaked — revoke everything issued from it.
    const replay = usedCodes.get(code);
    if (replay) {
      for (const token of replay.accessTokens) accessTokens.delete(token);
      return fail(400, "invalid_grant");
    }
    const issued = codes.get(code);
    codes.delete(code);
    if (!issued || issued.expiresAt <= Date.now()) return fail(400, "invalid_grant");
    if (issued.clientId !== clientId || issued.redirectUri !== req.body.redirect_uri) return fail(400, "invalid_grant");

    const verifier = typeof req.body.code_verifier === "string" ? req.body.code_verifier : "";
    if (!/^[A-Za-z0-9._~-]{43,128}$/.test(verifier)) return fail(400, "invalid_grant");
    const challenge = createHash("sha256").update(verifier).digest("base64url");
    if (!safeEqual(challenge, issued.codeChallenge)) return fail(400, "invalid_grant");

    const accessToken = randomToken();
    accessTokens.set(accessToken, { sub: issued.sub, expiresAt: Date.now() + ACCESS_TOKEN_TTL_MS });
    usedCodes.set(code, { accessTokens: [accessToken], expiresAt: Date.now() + ACCESS_TOKEN_TTL_MS });
    res.json({ access_token: accessToken, token_type: "Bearer", expires_in: ACCESS_TOKEN_TTL_MS / 1000, scope: issued.scope });
  });

  app.get("/userinfo", (req: Request, res: Response) => {
    const [scheme, token] = (req.get("authorization") ?? "").split(" ");
    const grant = scheme === "Bearer" && token ? accessTokens.get(token) : undefined;
    if (!grant || grant.expiresAt <= Date.now()) {
      res.set("WWW-Authenticate", 'Bearer error="invalid_token"').status(401).json({ error: "invalid_token" });
      return;
    }
    const identity = IDENTITIES.find((candidate) => candidate.sub === grant.sub)!;
    res.json(identity);
  });

  return app;
}
