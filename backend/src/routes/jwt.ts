import { Router, type Request, type Response } from "express";
import { IsNull } from "typeorm";
import { authenticatePassword, loginSchema, markLoggedIn, rejectIfMfaEnabled } from "../auth/credentials";
import { config } from "../config";
import { db, recordEvent } from "../db";
import { RefreshToken, type User } from "../db/entities";
import { clientInfo, cookieOptions, HttpError, parseBody, publicUser } from "../http";
import { randomToken, sha256 } from "../security/crypto";
import { signAccessToken } from "../security/jwt";

/** The refresh cookie is only ever sent to the JWT endpoints, never to the rest of the API. */
const COOKIE_PATH = "/api/auth/jwt";
const refreshTokens = () => db.getRepository(RefreshToken);
const INVALID_REFRESH = () => new HttpError(401, "invalid_refresh_token", "Please sign in again.");

async function issueTokens(res: Response, user: User, familyId: string) {
  const refreshToken = randomToken();
  await refreshTokens().insert({
    id: sha256(refreshToken),
    user,
    familyId,
    expiresAt: new Date(Date.now() + config.jwt.refreshTokenTtlMs),
    usedAt: null,
    revokedAt: null,
  });
  res.cookie(
    config.cookies.refreshName,
    refreshToken,
    cookieOptions({ path: COOKIE_PATH, sameSite: "strict", maxAge: config.jwt.refreshTokenTtlMs }),
  );
  const { token } = await signAccessToken(user.id, user.tokenVersion);
  // Access tokens must never be cached by browsers or intermediaries.
  res.set("Cache-Control", "no-store");
  return { accessToken: token, tokenType: "Bearer", expiresIn: config.jwt.accessTokenTtlSeconds };
}

function readRefreshCookie(req: Request): string | null {
  const token: unknown = req.cookies?.[config.cookies.refreshName];
  return typeof token === "string" && token.length <= 64 ? token : null;
}

export async function revokeFamily(familyId: string): Promise<void> {
  await refreshTokens().update({ familyId, revokedAt: IsNull() }, { revokedAt: new Date() });
}

export const jwtRoutes = Router();

/** Credentials → short-lived access token (response body, kept in memory) + rotating refresh token (HttpOnly cookie). */
jwtRoutes.post("/login", async (req, res) => {
  const user = await authenticatePassword(req, parseBody(loginSchema, req), "jwt");
  await rejectIfMfaEnabled(req, user, "jwt");
  const tokens = await issueTokens(res, user, randomToken(16));
  await markLoggedIn(req, user, "jwt.login");
  res.json({ ...tokens, user: publicUser(user) });
});

/**
 * Refresh-token rotation: each refresh token works exactly once and is replaced by a new one.
 * Presenting an already-used token means it was stolen (either the attacker or the user used it
 * first), so the whole token family is revoked and both parties must sign in again.
 */
jwtRoutes.post("/refresh", async (req, res) => {
  const token = readRefreshCookie(req);
  if (!token) throw INVALID_REFRESH();
  const stored = await refreshTokens().findOne({ where: { id: sha256(token) }, relations: { user: true } });
  if (!stored || stored.revokedAt || stored.expiresAt.getTime() <= Date.now()) throw INVALID_REFRESH();

  // Atomically claim the token; if another request already used it, this is reuse.
  const claim = await refreshTokens().update({ id: stored.id, usedAt: IsNull() }, { usedAt: new Date() });
  if (claim.affected !== 1) {
    await revokeFamily(stored.familyId);
    await recordEvent({
      type: "jwt.refresh",
      success: false,
      userId: stored.user.id,
      detail: "refresh token reuse detected; token family revoked",
      ...clientInfo(req),
    });
    res.clearCookie(config.cookies.refreshName, cookieOptions({ path: COOKIE_PATH, sameSite: "strict" }));
    throw INVALID_REFRESH();
  }

  res.json(await issueTokens(res, stored.user, stored.familyId));
});

jwtRoutes.post("/logout", async (req, res) => {
  const token = readRefreshCookie(req);
  if (token) {
    const stored = await refreshTokens().findOneBy({ id: sha256(token) });
    if (stored) await revokeFamily(stored.familyId);
  }
  res.clearCookie(config.cookies.refreshName, cookieOptions({ path: COOKIE_PATH, sameSite: "strict" }));
  res.status(204).end();
});
