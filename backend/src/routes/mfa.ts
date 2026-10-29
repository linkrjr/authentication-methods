import { randomBytes } from "node:crypto";
import { Router, type Request, type Response } from "express";
import QRCode from "qrcode";
import { z } from "zod";
import { authenticatePassword, loginSchema, markLoggedIn } from "../auth/credentials";
import { startSession } from "../auth/sessions";
import { config } from "../config";
import { db, recordEvent } from "../db";
import { MfaChallenge, RecoveryCode, User } from "../db/entities";
import { clientInfo, cookieOptions, HttpError, parseBody, publicUser } from "../http";
import { decrypt, encrypt, randomToken, sha256 } from "../security/crypto";
import { base32Encode, generateTotpSecret, otpauthUrl, verifyTotp } from "../security/totp";

const COOKIE_PATH = "/api/auth/mfa";
const codeSchema = z.object({ code: z.string().trim().min(6).max(32) });
const challenges = () => db.getRepository(MfaChallenge);

/** AAD binds an encrypted TOTP secret to its owner. */
const totpAad = (userId: string) => `totp:${userId}`;

export function decryptTotpSecret(user: User): Buffer {
  if (!user.totpSecretEnc) throw new Error("User has no TOTP secret");
  return decrypt(config.secrets.encryptionKey, user.totpSecretEnc, totpAad(user.id));
}

/** Checks a TOTP code for an enrolled user and burns its time-step (replay protection). */
export async function consumeTotp(user: User, code: string): Promise<boolean> {
  const step = verifyTotp(decryptTotpSecret(user), code, { lastUsedStep: user.totpLastUsedStep });
  if (step === null) return false;
  // Conditional update: if a concurrent request already consumed this step, nothing is updated.
  const result = await db
    .getRepository(User)
    .createQueryBuilder()
    .update()
    .set({ totpLastUsedStep: step })
    .where("id = :id AND (totpLastUsedStep IS NULL OR totpLastUsedStep < :step)", { id: user.id, step })
    .execute();
  user.totpLastUsedStep = step;
  return result.affected === 1;
}

/** 10 single-use codes of 50 bits each, e.g. "k3m9q-x2v7p". Only SHA-256 digests are stored. */
function generateRecoveryCodes(): string[] {
  return Array.from({ length: config.mfa.recoveryCodeCount }, () => {
    const raw = base32Encode(randomBytes(7)).slice(0, 10).toLowerCase();
    return `${raw.slice(0, 5)}-${raw.slice(5)}`;
  });
}

const normalizeRecoveryCode = (code: string) => code.toLowerCase().replace(/[^a-z0-9]/g, "");

async function consumeRecoveryCode(user: User, code: string): Promise<boolean> {
  const normalized = normalizeRecoveryCode(code);
  if (normalized.length !== 10) return false;
  const formatted = `${normalized.slice(0, 5)}-${normalized.slice(5)}`;
  const result = await db
    .getRepository(RecoveryCode)
    .createQueryBuilder()
    .update()
    .set({ usedAt: new Date() })
    .where("userId = :userId AND codeHash = :hash AND usedAt IS NULL", { userId: user.id, hash: sha256(formatted) })
    .execute();
  return result.affected === 1;
}

async function loadChallenge(req: Request): Promise<MfaChallenge> {
  const token: unknown = req.cookies?.[config.cookies.mfaChallengeName];
  const challenge =
    typeof token === "string" && token.length <= 64
      ? await challenges().findOne({ where: { id: sha256(token) }, relations: { user: true } })
      : null;
  if (!challenge || challenge.expiresAt.getTime() <= Date.now() || challenge.attempts >= config.mfa.maxAttempts) {
    if (challenge) await challenges().delete({ id: challenge.id });
    throw new HttpError(401, "challenge_expired", "Your sign-in attempt expired. Please start again.");
  }
  return challenge;
}

function clearChallengeCookie(res: Response) {
  res.clearCookie(config.cookies.mfaChallengeName, cookieOptions({ path: COOKIE_PATH, sameSite: "strict" }));
}

export const mfaRoutes = Router();

/**
 * Step 1: verify the password. Nothing is authenticated yet; the browser only receives a
 * short-lived, single-purpose challenge cookie. Users without MFA are enrolled on the spot.
 */
mfaRoutes.post("/login", async (req, res) => {
  const user = await authenticatePassword(req, parseBody(loginSchema, req), "mfa");
  await challenges().delete({ user: { id: user.id } });

  const token = randomToken();
  const pendingSecret = user.mfaEnabled ? null : generateTotpSecret();
  await challenges().insert({
    id: sha256(token),
    user,
    kind: pendingSecret ? "enroll" : "verify",
    pendingSecretEnc: pendingSecret ? encrypt(config.secrets.encryptionKey, pendingSecret, totpAad(user.id)) : null,
    attempts: 0,
    expiresAt: new Date(Date.now() + config.mfa.challengeTtlMs),
  });
  res.cookie(
    config.cookies.mfaChallengeName,
    token,
    cookieOptions({ path: COOKIE_PATH, sameSite: "strict", maxAge: config.mfa.challengeTtlMs }),
  );

  if (!pendingSecret) {
    res.json({ status: "mfa_required" });
    return;
  }
  const url = otpauthUrl(config.mfa.issuer, user.username ?? user.displayName, pendingSecret);
  res.json({
    status: "enrollment_required",
    otpauthUrl: url,
    secret: base32Encode(pendingSecret),
    qrCodeDataUrl: await QRCode.toDataURL(url, { margin: 1, width: 220 }),
  });
});

/** Step 2: TOTP code (or a recovery code) → session. */
mfaRoutes.post("/verify", async (req, res) => {
  const { code } = parseBody(codeSchema, req);
  const challenge = await loadChallenge(req);
  // Count the attempt atomically before checking, so parallel guesses cannot exceed the limit.
  await challenges().increment({ id: challenge.id }, "attempts", 1);
  const { attempts } = await challenges().findOneByOrFail({ id: challenge.id });
  const attemptsRemaining = config.mfa.maxAttempts - attempts;
  const user = challenge.user;
  const client = clientInfo(req);
  const compact = code.replace(/\s/g, "");

  let recoveryCodes: string[] | undefined;
  let valid: boolean;
  let detail: string;

  if (attemptsRemaining < 0) {
    valid = false;
    detail = "attempt limit exceeded";
  } else if (challenge.kind === "enroll") {
    const secret = decrypt(config.secrets.encryptionKey, challenge.pendingSecretEnc!, totpAad(user.id));
    const step = verifyTotp(secret, compact);
    valid = step !== null;
    detail = "TOTP enrollment";
    if (step !== null) {
      const codes = generateRecoveryCodes();
      await db.transaction(async (tx) => {
        await tx.getRepository(User).update(
          { id: user.id },
          { mfaEnabled: true, totpSecretEnc: challenge.pendingSecretEnc, totpLastUsedStep: step },
        );
        await tx.getRepository(RecoveryCode).delete({ user: { id: user.id } });
        await tx.getRepository(RecoveryCode).insert(codes.map((rc) => ({ user, codeHash: sha256(rc), usedAt: null })));
      });
      user.mfaEnabled = true;
      recoveryCodes = codes;
    }
  } else if (/^\d{6}$/.test(compact)) {
    valid = await consumeTotp(user, compact);
    detail = "TOTP code";
  } else {
    valid = await consumeRecoveryCode(user, code);
    detail = "recovery code";
  }

  if (!valid) {
    await recordEvent({ type: "mfa.verify", success: false, userId: user.id, detail, ...client });
    if (attemptsRemaining <= 0) {
      await challenges().delete({ id: challenge.id });
      clearChallengeCookie(res);
      throw new HttpError(401, "challenge_expired", "Too many invalid codes. Please start again.");
    }
    throw new HttpError(401, "invalid_code", "That code is not valid.", { attemptsRemaining });
  }

  await challenges().delete({ id: challenge.id });
  clearChallengeCookie(res);
  if (recoveryCodes) await recordEvent({ type: "mfa.enrolled", success: true, userId: user.id, ...client });
  await startSession(req, res, user, "mfa");
  await markLoggedIn(req, user, "mfa.login", detail);
  res.json({ status: "authenticated", user: publicUser(user), ...(recoveryCodes ? { recoveryCodes } : {}) });
});
