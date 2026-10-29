import type { RequestHandler } from "express";
import { config } from "../config";
import { cookieOptions, HttpError } from "../http";
import { randomToken, safeEqual } from "../security/crypto";

const SAFE_METHODS: Record<string, true> = { GET: true, HEAD: true, OPTIONS: true };
export const CSRF_HEADER = "x-csrf-token";

/** GET /api/auth/csrf — issues the token in the body and mirrors it in an HttpOnly cookie. */
export const issueCsrfToken: RequestHandler = (req, res) => {
  const existing: unknown = req.cookies?.[config.cookies.csrfName];
  const token = typeof existing === "string" && existing.length === 43 ? existing : randomToken();
  res.cookie(config.cookies.csrfName, token, cookieOptions({ sameSite: "strict" }));
  res.json({ csrfToken: token });
};

/**
 * Defence in depth for every state-changing request that may carry cookies:
 *  1. Origin / Fetch-Metadata check: cross-site browser requests are rejected outright.
 *  2. Double-submit token: the X-CSRF-Token header must equal the CSRF cookie. A cross-site
 *     attacker can make the browser send the cookie but cannot read it to set the header.
 * SameSite cookies are a third layer.
 */
export const csrfProtection: RequestHandler = (req, _res, next) => {
  if (SAFE_METHODS[req.method]) return next();

  const origin = req.get("origin");
  const fetchSite = req.get("sec-fetch-site");
  if (origin ? origin !== config.appOrigin : fetchSite !== undefined && fetchSite !== "same-origin") {
    throw new HttpError(403, "csrf_failed", "Cross-origin request rejected.");
  }

  const cookieToken: unknown = req.cookies?.[config.cookies.csrfName];
  const headerToken = req.get(CSRF_HEADER);
  if (typeof cookieToken !== "string" || !headerToken || !safeEqual(cookieToken, headerToken)) {
    throw new HttpError(403, "csrf_failed", "Missing or invalid CSRF token.");
  }
  next();
};
