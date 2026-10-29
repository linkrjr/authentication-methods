import { Router } from "express";
import { z } from "zod";
import { endAllSessions } from "../auth/sessions";
import { config } from "../config";
import { db, recordEvent } from "../db";
import { AuthEvent, RecoveryCode, RefreshToken, User } from "../db/entities";
import { clientInfo, cookieOptions, HttpError, parseBody, publicEvent, publicUser } from "../http";
import { authOf, requireAuth } from "../middleware/authenticate";
import { consumeTotp } from "./mfa";

export const meRoutes = Router();
meRoutes.use(requireAuth);

/** The single "you are signed in" resource every login method lands on. */
meRoutes.get("/", (_req, res) => {
  const auth = authOf(res);
  res.json({ user: publicUser(auth.user), auth: { method: auth.method, expiresAt: auth.expiresAt.toISOString() } });
});

meRoutes.get("/events", async (_req, res) => {
  const events = await db.getRepository(AuthEvent).find({
    where: { userId: authOf(res).user.id },
    order: { createdAt: "DESC" },
    take: 20,
  });
  res.json({ events: events.map(publicEvent) });
});

/** Revokes every session, refresh token and (via tokenVersion) every outstanding access token. */
meRoutes.post("/logout-all", async (req, res) => {
  const { user } = authOf(res);
  await db.transaction(async (tx) => {
    await tx.getRepository(User).increment({ id: user.id }, "tokenVersion", 1);
    await tx.getRepository(RefreshToken).delete({ user: { id: user.id } });
  });
  await endAllSessions(user.id);
  await recordEvent({ type: "account.logout_all", success: true, userId: user.id, ...clientInfo(req) });
  res.clearCookie(config.cookies.sessionName, cookieOptions());
  res.status(204).end();
});

/** Turning MFA off is a sensitive change, so it requires a fresh second-factor proof (step-up). */
meRoutes.post("/mfa/disable", async (req, res) => {
  const { code } = parseBody(z.object({ code: z.string().trim().regex(/^\d{6}$/, "Enter the 6-digit code") }), req);
  const { user } = authOf(res);
  if (!user.mfaEnabled) throw new HttpError(400, "mfa_not_enabled", "Multi-factor authentication is not enabled.");
  if (!(await consumeTotp(user, code))) {
    await recordEvent({ type: "mfa.disable", success: false, userId: user.id, detail: "invalid code", ...clientInfo(req) });
    throw new HttpError(401, "invalid_code", "That code is not valid.");
  }
  await db.transaction(async (tx) => {
    await tx.getRepository(User).update({ id: user.id }, { mfaEnabled: false, totpSecretEnc: null, totpLastUsedStep: null });
    await tx.getRepository(RecoveryCode).delete({ user: { id: user.id } });
  });
  await recordEvent({ type: "mfa.disable", success: true, userId: user.id, ...clientInfo(req) });
  res.status(204).end();
});
