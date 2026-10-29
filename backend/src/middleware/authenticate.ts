import type { RequestHandler, Response } from "express";
import { readSession, sessionExpiry } from "../auth/sessions";
import { db } from "../db";
import { User, type AuthMethod } from "../db/entities";
import { HttpError } from "../http";
import { verifyAccessToken } from "../security/jwt";

export interface AuthContext {
  user: User;
  method: AuthMethod;
  expiresAt: Date;
}

const UNAUTHENTICATED = () => new HttpError(401, "unauthenticated", "Authentication required.");

/**
 * Accepts either a Bearer access token (JWT flow) or a session cookie (password / OAuth / MFA flows).
 * When an Authorization header is present it is authoritative: an invalid token never falls back to cookies.
 */
export const requireAuth: RequestHandler = async (req, res, next) => {
  const header = req.get("authorization");
  if (header) {
    const [scheme, token] = header.split(" ");
    if (scheme !== "Bearer" || !token) throw UNAUTHENTICATED();
    const claims = await verifyAccessToken(token).catch(() => {
      throw UNAUTHENTICATED();
    });
    const user = await db.getRepository(User).findOneBy({ id: claims.sub });
    // Token version mismatch ⇒ revoked by "sign out everywhere".
    if (!user || user.tokenVersion !== claims.ver) throw UNAUTHENTICATED();
    res.locals.auth = { user, method: "jwt", expiresAt: new Date(claims.exp * 1000) } satisfies AuthContext;
    return next();
  }

  const session = await readSession(req);
  if (!session) throw UNAUTHENTICATED();
  res.locals.auth = { user: session.user, method: session.authMethod, expiresAt: sessionExpiry(session) } satisfies AuthContext;
  next();
};

export function authOf(res: Response): AuthContext {
  return res.locals.auth as AuthContext;
}
