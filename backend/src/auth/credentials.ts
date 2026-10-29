import type { Request } from "express";
import { z } from "zod";
import { config } from "../config";
import { db, recordEvent } from "../db";
import { User } from "../db/entities";
import { clientInfo, HttpError } from "../http";
import { hashPassword, needsRehash, verifyAgainstDummy, verifyPassword } from "../security/password";

const HANDLE = /^[a-z0-9_.-]{3,32}$/;
const EMAIL = z.email();

/**
 * The login identifier: a handle (3–32 letters, digits, '_', '.', '-') or an email address.
 * Canonical form for lookups: trimmed, NFKC, lower-case, so "Alice" and "alice" are one account.
 */
export const usernameSchema = z
  .string()
  .trim()
  .max(254, "Must be at most 254 characters")
  .transform((value) => value.normalize("NFKC").toLowerCase())
  .refine((value) => HANDLE.test(value) || EMAIL.safeParse(value).success, {
    message: "Use 3–32 letters, digits, '_', '.', '-', or a valid email address",
  });

/**
 * NIST SP 800-63B: favour length over composition rules. The upper bound stops
 * multi-megabyte inputs from being fed to the (deliberately expensive) hash function.
 */
export const newPasswordSchema = z
  .string()
  .min(12, "Must be at least 12 characters")
  .max(128, "Must be at most 128 characters");

export const loginSchema = z.object({
  username: z.string().max(254),
  password: z.string().max(128),
});

const INVALID = () => new HttpError(401, "invalid_credentials", "Invalid username or password.");

/**
 * Verifies username + password with:
 *  - one generic error for "unknown user", "wrong password" and "locked" (no account enumeration),
 *  - a dummy hash verification for unknown users (no timing oracle),
 *  - per-account lockout after repeated failures (online guessing), on top of per-IP rate limiting,
 *  - transparent rehash when cost parameters were raised.
 */
export async function authenticatePassword(req: Request, input: z.infer<typeof loginSchema>, flow: string): Promise<User> {
  const users = db.getRepository(User);
  const username = input.username.trim().normalize("NFKC").toLowerCase();
  const user = await users.findOneBy({ username });
  const client = clientInfo(req);

  if (!user?.passwordHash) {
    await verifyAgainstDummy(input.password);
    await recordEvent({ type: `${flow}.login`, success: false, detail: "unknown user", ...client });
    throw INVALID();
  }

  if (user.lockedUntil && user.lockedUntil.getTime() > Date.now()) {
    await verifyAgainstDummy(input.password);
    await recordEvent({ type: `${flow}.login`, success: false, userId: user.id, detail: "account locked", ...client });
    throw INVALID();
  }

  if (!(await verifyPassword(input.password, user.passwordHash))) {
    // Atomic increment: concurrent guesses cannot race past the threshold.
    await users.increment({ id: user.id }, "failedLoginAttempts", 1);
    const { failedLoginAttempts } = await users.findOneByOrFail({ id: user.id });
    const locked = failedLoginAttempts >= config.lockout.maxFailedAttempts;
    if (locked) {
      await users.update(
        { id: user.id },
        { failedLoginAttempts: 0, lockedUntil: new Date(Date.now() + config.lockout.durationMs) },
      );
    }
    await recordEvent({
      type: `${flow}.login`,
      success: false,
      userId: user.id,
      detail: locked ? "wrong password; account locked for 15 minutes" : "wrong password",
      ...client,
    });
    throw INVALID();
  }

  user.failedLoginAttempts = 0;
  user.lockedUntil = null;
  if (needsRehash(user.passwordHash)) user.passwordHash = await hashPassword(input.password);
  await users.update(
    { id: user.id },
    { failedLoginAttempts: 0, lockedUntil: null, passwordHash: user.passwordHash },
  );
  return user;
}

/** Final step of every successful login, whatever the method. */
export async function markLoggedIn(req: Request, user: User, type: string, detail?: string): Promise<void> {
  user.lastLoginAt = new Date();
  await db.getRepository(User).update({ id: user.id }, { lastLoginAt: user.lastLoginAt });
  await recordEvent({ type, success: true, userId: user.id, detail, ...clientInfo(req) });
}

/** Password-only flows must refuse accounts protected by a second factor. */
export async function rejectIfMfaEnabled(req: Request, user: User, flow: string): Promise<void> {
  if (!user.mfaEnabled) return;
  await recordEvent({ type: `${flow}.login`, success: false, userId: user.id, detail: "MFA required", ...clientInfo(req) });
  throw new HttpError(403, "mfa_required", "This account has multi-factor authentication enabled. Use the MFA login.");
}
