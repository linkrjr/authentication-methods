import path from "node:path";

const env = process.env;
const isProduction = env.NODE_ENV === "production";
const isTest = env.NODE_ENV === "test";

function required(name: string): string {
  const value = env[name];
  if (!value) {
    throw new Error(
      `Missing required environment variable ${name}. Run \`bun scripts/ensure-env.ts\` (backend/) to generate a local .env.`,
    );
  }
  return value;
}

/** Secrets are 32+ random bytes, base64-encoded. Weak/short secrets are rejected at boot. */
function secretBytes(name: string): Buffer {
  const bytes = Buffer.from(required(name), "base64");
  if (bytes.length < 32) throw new Error(`${name} must decode to at least 32 bytes`);
  return bytes;
}

function int(name: string, fallback: number): number {
  const raw = env[name];
  if (raw === undefined || raw === "") return fallback;
  const value = Number.parseInt(raw, 10);
  if (!Number.isFinite(value)) throw new Error(`${name} must be an integer`);
  return value;
}

const appOrigin = new URL(env.APP_ORIGIN ?? "http://localhost:5173").origin;
const oauthProviderUrl = new URL(env.OAUTH_PROVIDER_URL ?? "http://localhost:4000").origin;
const cookieSecure = env.COOKIE_SECURE ? env.COOKIE_SECURE === "true" : isProduction;

export const config = {
  isProduction,
  isTest,
  port: int("PORT", 3000),
  /** Public origin of the web app. Used for CSRF origin checks and post-login redirects. */
  appOrigin,
  databasePath: env.DATABASE_PATH ?? path.join(import.meta.dir, "..", "data", "app.sqlite"),
  /** Express `trust proxy` setting; only enable behind a proxy you control, otherwise X-Forwarded-For is spoofable. */
  trustProxy: int("TRUST_PROXY_HOPS", 0),
  frontendDist: path.join(import.meta.dir, "..", "..", "frontend", "dist"),

  secrets: {
    /** HMAC key mixed into every password before argon2id ("pepper"); lives outside the database. */
    passwordPepper: secretBytes("PASSWORD_PEPPER"),
    /** AES-256-GCM key for data encrypted at rest (TOTP secrets). */
    encryptionKey: secretBytes("ENCRYPTION_KEY").subarray(0, 32),
    jwtSecret: secretBytes("JWT_SECRET"),
  },

  cookies: {
    secure: cookieSecure,
    /** `__Host-` prefix forbids Domain= and requires Secure + Path=/, blocking subdomain cookie tossing. */
    sessionName: cookieSecure ? "__Host-sid" : "sid",
    csrfName: cookieSecure ? "__Host-csrf" : "csrf",
    refreshName: "rt",
    mfaChallengeName: "mfa_challenge",
    oauthStateName: "oauth_state",
  },

  session: {
    idleTimeoutMs: 30 * 60 * 1000,
    absoluteTimeoutMs: 8 * 60 * 60 * 1000,
  },

  lockout: {
    maxFailedAttempts: 5,
    durationMs: 15 * 60 * 1000,
  },

  rateLimit: {
    windowMs: 15 * 60 * 1000,
    maxAuthRequests: int("AUTH_RATE_LIMIT_MAX", 30),
  },

  jwt: {
    issuer: "auth-patterns-api",
    audience: "auth-patterns-web",
    accessTokenTtlSeconds: 10 * 60,
    refreshTokenTtlMs: 7 * 24 * 60 * 60 * 1000,
  },

  mfa: {
    issuer: "Auth Patterns Demo",
    challengeTtlMs: 5 * 60 * 1000,
    maxAttempts: 5,
    recoveryCodeCount: 10,
  },

  oauth: {
    providerPort: int("OAUTH_PROVIDER_PORT", 4000),
    /** Browser-facing URL of the (mock) authorization server. */
    providerUrl: oauthProviderUrl,
    clientId: env.OAUTH_DEMO_CLIENT_ID ?? "auth-patterns-demo",
    clientSecret: required("OAUTH_DEMO_CLIENT_SECRET"),
    redirectUri: `${appOrigin}/api/auth/oauth/demo/callback`,
    stateTtlMs: 10 * 60 * 1000,
  },
} as const;

export type Config = typeof config;
