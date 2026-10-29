import { createHash } from "node:crypto";
import { Router, type Request } from "express";
import { z } from "zod";
import { markLoggedIn } from "../auth/credentials";
import { startSession } from "../auth/sessions";
import { config } from "../config";
import { db, recordEvent } from "../db";
import { OAuthAccount, OAuthState, User } from "../db/entities";
import { clientInfo, cookieOptions } from "../http";
import { randomToken, safeEqual, sha256 } from "../security/crypto";

/**
 * OAuth 2.0 Authorization Code flow with PKCE (RFC 7636), as a confidential client.
 * Provider endpoints point at the bundled mock authorization server ("DemoID"); a real
 * provider (GitHub, Google, ...) only needs different URLs, credentials and profile mapping.
 */
const PROVIDER = "demo";
const COOKIE_PATH = `/api/auth/oauth/${PROVIDER}`;
const endpoints = {
  authorize: `${config.oauth.providerUrl}/authorize`,
  token: `${config.oauth.providerUrl}/token`,
  userinfo: `${config.oauth.providerUrl}/userinfo`,
};

const tokenResponseSchema = z.object({ access_token: z.string().min(1), token_type: z.literal("Bearer") });
const profileSchema = z.object({ sub: z.string().min(1).max(255), name: z.string().max(128), email: z.email().nullable() });

class OAuthFlowError extends Error {
  constructor(readonly code: "access_denied" | "invalid_state" | "oauth_failed", detail: string) {
    super(detail);
  }
}

export const oauthRoutes = Router();

oauthRoutes.get(`/${PROVIDER}/start`, async (_req, res) => {
  const state = randomToken();
  const codeVerifier = randomToken(32); // 43 chars, within RFC 7636's 43–128
  const codeChallenge = createHash("sha256").update(codeVerifier).digest("base64url");

  await db.getRepository(OAuthState).insert({
    id: sha256(state),
    provider: PROVIDER,
    codeVerifier,
    expiresAt: new Date(Date.now() + config.oauth.stateTtlMs),
  });
  // Binds this authorization request to this browser: a callback carrying someone else's
  // `state` (login CSRF / authorization-code injection) will not match the cookie.
  res.cookie(config.cookies.oauthStateName, state, cookieOptions({ path: COOKIE_PATH, maxAge: config.oauth.stateTtlMs }));

  const url = new URL(endpoints.authorize);
  url.search = new URLSearchParams({
    response_type: "code",
    client_id: config.oauth.clientId,
    redirect_uri: config.oauth.redirectUri,
    scope: "openid profile email",
    state,
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
  }).toString();
  res.redirect(302, url.toString());
});

async function consumeState(req: Request): Promise<string> {
  const queryState = req.query.state;
  const cookieState: unknown = req.cookies?.[config.cookies.oauthStateName];
  if (typeof queryState !== "string" || typeof cookieState !== "string" || !safeEqual(queryState, cookieState)) {
    throw new OAuthFlowError("invalid_state", "state mismatch");
  }
  const states = db.getRepository(OAuthState);
  const stored = await states.findOneBy({ id: sha256(queryState) });
  // Single use: delete before anything else can go wrong.
  if (stored) await states.delete({ id: stored.id });
  if (!stored || stored.provider !== PROVIDER || stored.expiresAt.getTime() <= Date.now()) {
    throw new OAuthFlowError("invalid_state", "unknown or expired state");
  }
  return stored.codeVerifier;
}

async function exchangeCode(code: string, codeVerifier: string) {
  const basic = Buffer.from(
    `${encodeURIComponent(config.oauth.clientId)}:${encodeURIComponent(config.oauth.clientSecret)}`,
  ).toString("base64");
  const tokenResponse = await fetch(endpoints.token, {
    method: "POST",
    headers: { authorization: `Basic ${basic}`, "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: config.oauth.redirectUri,
      code_verifier: codeVerifier,
    }),
    signal: AbortSignal.timeout(5000),
  });
  if (!tokenResponse.ok) throw new OAuthFlowError("oauth_failed", `token endpoint returned ${tokenResponse.status}`);
  const tokens = tokenResponseSchema.parse(await tokenResponse.json());

  const profileResponse = await fetch(endpoints.userinfo, {
    headers: { authorization: `Bearer ${tokens.access_token}`, accept: "application/json" },
    signal: AbortSignal.timeout(5000),
  });
  if (!profileResponse.ok) throw new OAuthFlowError("oauth_failed", `userinfo returned ${profileResponse.status}`);
  return profileSchema.parse(await profileResponse.json());
}

/**
 * Accounts are keyed by (provider, sub). Matching an existing local account by e-mail would let
 * anyone who controls that address at the provider take the account over, so it is never done.
 */
async function findOrCreateUser(profile: z.infer<typeof profileSchema>): Promise<User> {
  return db.transaction(async (tx) => {
    const accounts = tx.getRepository(OAuthAccount);
    const linked = await accounts.findOne({ where: { provider: PROVIDER, subject: profile.sub }, relations: { user: true } });
    if (linked) return linked.user;
    const user = await tx.getRepository(User).save(
      tx.getRepository(User).create({ username: null, displayName: profile.name, email: profile.email, passwordHash: null }),
    );
    await accounts.insert({ provider: PROVIDER, subject: profile.sub, user });
    return user;
  });
}

oauthRoutes.get(`/${PROVIDER}/callback`, async (req, res) => {
  res.clearCookie(config.cookies.oauthStateName, cookieOptions({ path: COOKIE_PATH }));
  try {
    const codeVerifier = await consumeState(req);
    if (typeof req.query.error === "string") {
      throw new OAuthFlowError(req.query.error === "access_denied" ? "access_denied" : "oauth_failed", `provider error: ${req.query.error}`);
    }
    if (typeof req.query.code !== "string" || req.query.code.length > 256) throw new OAuthFlowError("oauth_failed", "missing code");

    const profile = await exchangeCode(req.query.code, codeVerifier);
    const user = await findOrCreateUser(profile);
    await startSession(req, res, user, "oauth");
    await markLoggedIn(req, user, "oauth.login", `provider: ${PROVIDER}`);
    res.redirect(303, `${config.appOrigin}/dashboard`);
  } catch (error) {
    const flowError = error instanceof OAuthFlowError ? error : new OAuthFlowError("oauth_failed", String(error));
    await recordEvent({ type: "oauth.login", success: false, detail: flowError.message, ...clientInfo(req) });
    // Only a fixed error code is reflected to the browser — never provider-supplied text.
    res.redirect(303, `${config.appOrigin}/login/oauth?error=${flowError.code}`);
  }
});
