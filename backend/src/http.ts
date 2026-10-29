import type { CookieOptions, ErrorRequestHandler, Request, Response } from "express";
import { z } from "zod";
import { config } from "./config";
import type { AuthEvent, User } from "./db/entities";

export class HttpError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly extra: Record<string, unknown> = {},
  ) {
    super(message);
  }
}

/** Validates untrusted input; failures become 400 with per-field issues. */
export function parseBody<T extends z.ZodType>(schema: T, req: Request): z.infer<T> {
  const result = schema.safeParse(req.body ?? {});
  if (!result.success) {
    throw new HttpError(400, "validation_failed", "Some fields are invalid.", {
      issues: result.error.issues.map((issue) => ({ path: issue.path.join("."), message: issue.message })),
    });
  }
  return result.data;
}

export function clientInfo(req: Request): { ip: string | null; userAgent: string | null } {
  return { ip: req.ip ?? null, userAgent: req.get("user-agent")?.slice(0, 256) ?? null };
}

/** HttpOnly (no JS access), SameSite (no cross-site sends), Secure in production. */
export function cookieOptions(overrides: CookieOptions = {}): CookieOptions {
  return { httpOnly: true, secure: config.cookies.secure, sameSite: "lax", path: "/", ...overrides };
}

export function publicUser(user: User) {
  return {
    id: user.id,
    username: user.username,
    displayName: user.displayName,
    email: user.email,
    mfaEnabled: user.mfaEnabled,
    createdAt: user.createdAt.toISOString(),
    lastLoginAt: user.lastLoginAt?.toISOString() ?? null,
  };
}

export function publicEvent(event: AuthEvent) {
  return {
    id: event.id,
    type: event.type,
    success: event.success,
    detail: event.detail,
    ip: event.ip,
    userAgent: event.userAgent,
    createdAt: event.createdAt.toISOString(),
  };
}

export const errorHandler: ErrorRequestHandler = (err, _req, res: Response, _next) => {
  if (err instanceof HttpError) {
    res.status(err.status).json({ error: err.code, message: err.message, ...err.extra });
    return;
  }
  // body-parser errors (malformed JSON, payload too large) carry a 4xx status.
  const status = typeof err?.status === "number" && err.status >= 400 && err.status < 500 ? err.status : 500;
  if (status === 500) console.error(err);
  // Never leak stack traces or internal messages to clients.
  res.status(status).json({
    error: status === 500 ? "internal_error" : "bad_request",
    message: status === 500 ? "Something went wrong." : "Malformed request.",
  });
};
