# Authentication Patterns Demo

A small full-stack app that shows four ways to sign in, each with its own login view. Whichever method you use, you land on the same `/dashboard`.

| Method | View | What you get after signing in |
|---|---|---|
| Username + password | `/login/password` | Server-side session in an HttpOnly cookie |
| OAuth 2.0 (authorization code + PKCE) | `/login/oauth` | Session cookie, after you consent at the bundled mock identity provider "DemoID" |
| MFA (password + TOTP) | `/login/mfa` | Session cookie. The first login enrolls an authenticator app and gives you recovery codes |
| Token based (JWT) | `/login/jwt` | A short-lived access token held in memory, plus a rotating refresh token in an HttpOnly cookie |

**Stack**
- Backend: Bun, Express 5, TypeScript, TypeORM and SQLite.
- Frontend: React, TanStack Router, TanStack Query and Vite.

## Run it

```bash
bun install
bun run dev        # API :3000, mock OAuth provider :4000, web app :5173
```

Open http://localhost:5173, create an account under **Register**, then try each login view. On the first `bun run dev`, `backend/.env` is created from `.env.example` with random secrets. Keep that file: if you change `PASSWORD_PEPPER`, every stored password hash stops working, and if you change `ENCRYPTION_KEY`, every stored TOTP secret stops working.

Other commands:

```bash
bun run test       # backend test suite (unit tests + full HTTP flows against both servers)
bun run typecheck
bun run build && APP_ORIGIN=http://localhost:3000 bun run start   # production mode: Express serves the built SPA on :3000
```

Notes:
- Once an account has MFA enabled, the password and JWT views refuse it with `mfa_required`. To use those views again, disable MFA from the dashboard (this asks for a current code), or register a second account.
- The JWT view shares accounts with the password and MFA views. OAuth accounts are created at the identity provider.

## Layout

```
backend/src
  config.ts                 env parsing; fails fast on missing or short secrets
  db/                       TypeORM entities, data source, bun:sqlite adapter
  security/                 password hashing, AES-GCM, TOTP (RFC 6238), JWT
  auth/                     credential checks with lockout, server-side sessions
  middleware/               CSRF, authentication (Bearer token or session cookie)
  routes/                   password · oauth · mfa · jwt · me
  oauth-provider/server.ts  mock OAuth 2.0 authorization server ("DemoID")
backend/test                bun tests
frontend/src                api client, in-memory token store, routes, pages
```

> Bun cannot load the native `better-sqlite3` module. TypeORM's better-sqlite3 driver accepts a custom driver, so `db/bun-sqlite-driver.ts` passes it a small adapter over `bun:sqlite`.

## Security controls

**Passwords**
- **argon2id** (64 MiB, t=3) through `Bun.password`. Every hash gets its own random 32-byte **salt**, stored in the PHC string (`$argon2id$v=19$m=65536,t=3,p=1$<salt>$<hash>`).
- Before hashing, the password is put through an **HMAC-SHA256 pepper**. The pepper key lives in the environment, not the database.
- Passwords are NFKC-normalized.
- Hashes are upgraded transparently when the cost settings are raised.
- Password rules follow NIST 800-63B: 12–128 characters, no composition rules, and the password must not contain the username (for an email, the part before `@`).
- The sign-in identifier is either a handle (3–32 letters, digits, `_`, `.`, `-`) or an email address. Both are matched case-insensitively.
- **No account enumeration.** The error is the same for an unknown user, a wrong password and a locked account. Unknown users still go through a dummy hash check, so the response time doesn't reveal whether the account exists.
- **Account lockout:** 5 failures lock the account for 15 minutes. The counter is incremented atomically.
- **Rate limiting** per IP on every endpoint that checks a secret.

**Sessions** (used by the password, OAuth and MFA logins)
- 256-bit random IDs. The database stores only their SHA-256.
- A fresh ID is issued at every login, which blocks session fixation.
- Idle timeout of 30 minutes and an absolute timeout of 8 hours.
- Cookies are `HttpOnly` and `SameSite`, plus `Secure` with the `__Host-` prefix in production.
- "Sign out everywhere" revokes every session and token the account has.

**CSRF**
- Every state-changing request is checked against the `Origin` / `Sec-Fetch-Site` headers.
- On top of that, a double-submit token must be sent: the `X-CSRF-Token` header has to match the CSRF cookie.
- The API sends `Referrer-Policy: same-origin`, not `no-referrer`. With `no-referrer`, browsers send `Origin: null` and the origin check would fail.

**OAuth 2.0**
- Authorization code flow with **PKCE S256**.
- `state` is bound to the browser with an HttpOnly cookie and is single-use. This protects against login CSRF and code injection.
- The code verifier stays on the server.
- The client authenticates to the token endpoint with `client_secret_basic`.
- Accounts are linked only by (provider, `sub`), **never by email**, so controlling an email address at the provider can't take over an account.
- Errors are reported back to the browser only as fixed codes, never as text supplied by the provider.
- The mock provider itself enforces:
  - an exact `redirect_uri` match (no redirect to unregistered URIs);
  - authorization codes that last 60 seconds and work once (replaying a code revokes the tokens issued from it);
  - a constant-time check of the client secret;
  - CSRF protection on the consent form;
  - a strict CSP on the consent page, with style nonces and `frame-ancestors 'none'`.

**MFA**
- TOTP per RFC 6238 (verified against the RFC test vectors), allowing ±1 time step of clock drift.
- **Replay protection:** an accepted time step can't be used again. This is enforced with a conditional update, so two simultaneous requests can't both succeed.
- The TOTP secret is **encrypted at rest with AES-256-GCM**, and the user ID is used as additional authenticated data (AAD) so the ciphertext can't be moved to another account.
- The step-1 challenge lives in an HttpOnly cookie for 5 minutes and allows at most 5 attempts.
- 10 single-use **recovery codes**, stored as hashes.
- Disabling MFA requires a fresh code (step-up authentication).

**JWT**
- HS256 access tokens that live for 10 minutes.
- The verifier pins the algorithm (blocking `alg=none` and algorithm-confusion attacks), the issuer, the audience and `typ: at+jwt`, and requires `exp`.
- The access token is kept **only in JavaScript memory**, never in `localStorage`.
- The refresh token is opaque and stored as a hash. Its cookie is `HttpOnly`, `SameSite=Strict` and limited to `/api/auth/jwt`.
- **Refresh tokens rotate on every use.** If a token that was already used is presented again, every token descended from the same login is revoked.
- A `ver` claim tied to the user's token version lets "sign out everywhere" kill access tokens that haven't expired yet.

**General**
- Security headers from Helmet: CSP, HSTS, `nosniff` and frame protection.
- `Cache-Control: no-store` on every API response.
- 10 kB limit on request bodies.
- Input validated with Zod.
- Stack traces are never sent to clients.
- An audit log of sign-in events is shown on the dashboard.

## Deliberate simplifications

- The OAuth provider is a local mock with two fixed identities and in-memory state. To use a real provider (GitHub, Google, …), change the endpoint URLs, client credentials and profile mapping in `routes/oauth.ts`.
- The schema is created with TypeORM `synchronize`. A real deployment would use migrations.
- Rate-limit counters are kept in memory, so they only work for a single process. Several instances would need a shared store such as Redis.
- Production should also check new passwords against a breached-password list (for example the k-anonymity API of Have I Been Pwned) and send security notifications by email.
