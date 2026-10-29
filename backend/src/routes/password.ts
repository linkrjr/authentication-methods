import { Router } from "express";
import { z } from "zod";
import { authenticatePassword, loginSchema, markLoggedIn, newPasswordSchema, rejectIfMfaEnabled, usernameSchema } from "../auth/credentials";
import { endSession, startSession } from "../auth/sessions";
import { db, recordEvent } from "../db";
import { User } from "../db/entities";
import { clientInfo, HttpError, parseBody, publicUser } from "../http";
import { hashPassword } from "../security/password";

const registerSchema = z
  .object({
    username: usernameSchema,
    password: newPasswordSchema,
    displayName: z.string().trim().max(64).optional(),
  })
  // For an email identifier, compare against its local part ("ada" in "ada@example.com"); local
  // parts shorter than 3 characters would reject far too many passwords to be useful.
  .refine(
    (input) => {
      const name = input.username.split("@")[0]!;
      return name.length < 3 || !input.password.toLowerCase().includes(name);
    },
    { path: ["password"], message: "Password must not contain the username" },
  );

export const passwordRoutes = Router();

passwordRoutes.post("/register", async (req, res) => {
  const input = parseBody(registerSchema, req);
  const users = db.getRepository(User);
  if (await users.existsBy({ username: input.username })) {
    throw new HttpError(409, "username_taken", "That username is already taken.");
  }
  const user = users.create({
    username: input.username,
    displayName: input.displayName || input.username,
    email: input.username.includes("@") ? input.username : null,
    passwordHash: await hashPassword(input.password),
  });
  // The UNIQUE index is the real guard; the pre-check above only gives a friendlier error.
  await users.save(user).catch((error: unknown) => {
    if (String(error).includes("UNIQUE")) throw new HttpError(409, "username_taken", "That username is already taken.");
    throw error;
  });
  await recordEvent({ type: "account.register", success: true, userId: user.id, ...clientInfo(req) });
  res.status(201).json({ user: publicUser(user) });
});

/** Classic username + password → server-side session in an HttpOnly cookie. */
passwordRoutes.post("/password/login", async (req, res) => {
  const user = await authenticatePassword(req, parseBody(loginSchema, req), "password");
  await rejectIfMfaEnabled(req, user, "password");
  await startSession(req, res, user, "password");
  await markLoggedIn(req, user, "password.login");
  res.json({ user: publicUser(user) });
});

/** Ends the cookie session (password, OAuth and MFA logins). */
passwordRoutes.post("/logout", async (req, res) => {
  await endSession(req, res);
  res.status(204).end();
});
