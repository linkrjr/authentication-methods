import { randomBytes } from "node:crypto";

// Isolated configuration for the test run (overrides anything loaded from backend/.env).
Object.assign(process.env, {
  NODE_ENV: "test",
  DATABASE_PATH: ":memory:",
  APP_ORIGIN: "http://localhost:4800",
  PORT: "4800",
  OAUTH_PROVIDER_PORT: "4801",
  OAUTH_PROVIDER_URL: "http://localhost:4801",
  OAUTH_DEMO_CLIENT_ID: "test-client",
  OAUTH_DEMO_CLIENT_SECRET: randomBytes(32).toString("base64"),
  PASSWORD_PEPPER: randomBytes(32).toString("base64"),
  ENCRYPTION_KEY: randomBytes(32).toString("base64"),
  JWT_SECRET: randomBytes(32).toString("base64"),
  AUTH_RATE_LIMIT_MAX: "10000",
  COOKIE_SECURE: "false",
});
