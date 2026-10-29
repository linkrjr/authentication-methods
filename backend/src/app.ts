import { existsSync } from "node:fs";
import path from "node:path";
import cookieParser from "cookie-parser";
import express from "express";
import { rateLimit } from "express-rate-limit";
import helmet from "helmet";
import { config } from "./config";
import { errorHandler, HttpError } from "./http";
import { csrfProtection, issueCsrfToken } from "./middleware/csrf";
import { jwtRoutes } from "./routes/jwt";
import { meRoutes } from "./routes/me";
import { mfaRoutes } from "./routes/mfa";
import { oauthRoutes } from "./routes/oauth";
import { passwordRoutes } from "./routes/password";

export function createApp() {
  const app = express();
  app.set("trust proxy", config.trustProxy);
  // Security headers: CSP, HSTS, X-Content-Type-Options, frame-ancestors/X-Frame-Options, ...
  // Referrer-Policy "same-origin" (not helmet's "no-referrer"): under no-referrer browsers send
  // `Origin: null` on same-origin POSTs, which would defeat the CSRF origin check.
  app.use(helmet({ referrerPolicy: { policy: "same-origin" } }));
  app.use(cookieParser());
  // Small body limit: auth payloads are tiny; large bodies are only useful for DoS.
  app.use(express.json({ limit: "10kb" }));

  // Per-IP throttling of every endpoint that checks a secret (password, TOTP, recovery code).
  const credentialLimiter = rateLimit({
    windowMs: config.rateLimit.windowMs,
    limit: config.rateLimit.maxAuthRequests,
    standardHeaders: "draft-8",
    legacyHeaders: false,
    handler: (_req, _res, next) => next(new HttpError(429, "too_many_requests", "Too many attempts. Please wait and try again.")),
  });

  const api = express.Router();
  api.use((_req, res, next) => {
    res.set("Cache-Control", "no-store");
    next();
  });
  api.use(csrfProtection);
  api.get("/auth/csrf", issueCsrfToken);
  api.post(
    ["/auth/register", "/auth/password/login", "/auth/mfa/login", "/auth/mfa/verify", "/auth/jwt/login", "/me/mfa/disable"],
    credentialLimiter,
  );
  api.use("/auth", passwordRoutes);
  api.use("/auth/oauth", oauthRoutes);
  api.use("/auth/mfa", mfaRoutes);
  api.use("/auth/jwt", jwtRoutes);
  api.use("/me", meRoutes);
  api.use(() => {
    throw new HttpError(404, "not_found", "Not found.");
  });
  app.use("/api", api);

  // Production: serve the built SPA from the same origin, so cookies stay first-party.
  if (config.isProduction && existsSync(config.frontendDist)) {
    app.use(express.static(config.frontendDist, { index: false }));
    app.use((req, res, next) => {
      if (req.method !== "GET") return next();
      res.sendFile(path.join(config.frontendDist, "index.html"));
    });
  }

  app.use(errorHandler);
  return app;
}
