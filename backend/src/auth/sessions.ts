import type { Request, Response } from "express";
import { config } from "../config";
import { db } from "../db";
import { Session, type AuthMethod, type User } from "../db/entities";
import { clientInfo, cookieOptions } from "../http";
import { randomToken, sha256 } from "../security/crypto";

const sessions = () => db.getRepository(Session);
const LAST_SEEN_WRITE_INTERVAL_MS = 60 * 1000;

/**
 * Issues a brand-new session id at every login and discards any id the browser already had,
 * so a pre-planted session id cannot be elevated (session fixation).
 */
export async function startSession(req: Request, res: Response, user: User, authMethod: AuthMethod): Promise<Session> {
  await endSession(req, res);
  const token = randomToken();
  const now = new Date();
  const session = sessions().create({
    id: sha256(token),
    user,
    authMethod,
    lastSeenAt: now,
    expiresAt: new Date(now.getTime() + config.session.absoluteTimeoutMs),
    ...clientInfo(req),
  });
  await sessions().insert(session);
  res.cookie(config.cookies.sessionName, token, cookieOptions({ maxAge: config.session.absoluteTimeoutMs }));
  return session;
}

/** Resolves the session cookie, enforcing both the idle and the absolute timeout. */
export async function readSession(req: Request): Promise<Session | null> {
  const token: unknown = req.cookies?.[config.cookies.sessionName];
  if (typeof token !== "string" || token.length > 64) return null;
  const session = await sessions().findOne({ where: { id: sha256(token) }, relations: { user: true } });
  if (!session) return null;
  const now = Date.now();
  if (session.expiresAt.getTime() <= now || session.lastSeenAt.getTime() + config.session.idleTimeoutMs <= now) {
    await sessions().delete({ id: session.id });
    return null;
  }
  if (now - session.lastSeenAt.getTime() > LAST_SEEN_WRITE_INTERVAL_MS) {
    session.lastSeenAt = new Date(now);
    await sessions().update({ id: session.id }, { lastSeenAt: session.lastSeenAt });
  }
  return session;
}

/** Effective expiry: whichever of idle / absolute timeout comes first. */
export function sessionExpiry(session: Session): Date {
  return new Date(Math.min(session.expiresAt.getTime(), session.lastSeenAt.getTime() + config.session.idleTimeoutMs));
}

export async function endSession(req: Request, res: Response): Promise<void> {
  const token: unknown = req.cookies?.[config.cookies.sessionName];
  if (typeof token === "string") await sessions().delete({ id: sha256(token) });
  res.clearCookie(config.cookies.sessionName, cookieOptions());
}

export async function endAllSessions(userId: string): Promise<void> {
  await sessions().delete({ user: { id: userId } });
}
