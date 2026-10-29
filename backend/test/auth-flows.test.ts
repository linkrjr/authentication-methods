import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { config } from "../src/config";
import { db } from "../src/db";
import { User } from "../src/db/entities";
import { signAccessToken } from "../src/security/jwt";
import { API, Browser, PASSWORD, PROVIDER, startServers, stopServers, totpCode, uniqueName } from "./harness";

beforeAll(startServers);
afterAll(stopServers);

async function register(browser: Browser, username = uniqueName("user")) {
  const response = await browser.post("/api/auth/register", { username, password: PASSWORD });
  expect(response.status).toBe(201);
  return username;
}

async function me(browser: Browser, headers?: Record<string, string>) {
  const response = await browser.get("/api/me", headers);
  return { status: response.status, body: (await response.json()) as { user: { id: string }; auth: { method: string } } };
}

describe("CSRF protection", () => {
  test("rejects state-changing requests without a token or from another origin", async () => {
    const browser = new Browser();
    const noToken = await browser.request("POST", "/api/auth/password/login", { body: { username: "x", password: "y" } });
    expect(noToken.status).toBe(403);
    expect(((await noToken.json()) as { error: string }).error).toBe("csrf_failed");

    const crossSite = await browser.post("/api/auth/password/login", { username: "x", password: "y" }, { origin: "https://evil.example" });
    expect(crossSite.status).toBe(403);
  });
});

describe("username + password (session cookie)", () => {
  test("identifier may be a handle with _ . - or an email address", async () => {
    const browser = new Browser();
    const handle = `${uniqueName("a_b.c-")}`;
    expect((await browser.post("/api/auth/register", { username: handle, password: PASSWORD })).status).toBe(201);

    const email = `${uniqueName("ada.lovelace+demo")}@example.com`;
    const created = await browser.post("/api/auth/register", { username: email, password: PASSWORD });
    expect(created.status).toBe(201);
    expect(((await created.json()) as { user: { email: string } }).user.email).toBe(email);
    const login = await browser.post("/api/auth/password/login", { username: email.toUpperCase(), password: PASSWORD });
    expect(login.status).toBe(200);

    for (const username of ["ab", "has space", "no@domain", "a".repeat(33)]) {
      expect((await browser.post("/api/auth/register", { username, password: PASSWORD })).status).toBe(400);
    }
  });

  test("register validates input and refuses duplicates", async () => {
    const browser = new Browser();
    const weak = await browser.post("/api/auth/register", { username: "ok_name", password: "short" });
    expect(weak.status).toBe(400);
    const username = await register(browser);
    const duplicate = await browser.post("/api/auth/register", { username: username.toUpperCase(), password: PASSWORD });
    expect(duplicate.status).toBe(409);
  });

  test("login issues a fresh HttpOnly session; logout destroys it", async () => {
    const browser = new Browser();
    const username = await register(browser);
    browser.cookies.set("sid", "attacker-planted-session-id");

    const login = await browser.post("/api/auth/password/login", { username, password: PASSWORD });
    expect(login.status).toBe(200);
    const sid = browser.cookies.get("sid");
    expect(sid).toBeDefined();
    expect(sid).not.toBe("attacker-planted-session-id"); // session fixation defence
    const header = browser.setCookieHeaders.find((h) => h.startsWith("sid=") && !h.startsWith("sid=;"))!;
    expect(header).toContain("HttpOnly");
    expect(header).toContain("SameSite=Lax");

    const current = await me(browser);
    expect(current.status).toBe(200);
    expect(current.body.auth.method).toBe("password");

    expect((await browser.post("/api/auth/logout")).status).toBe(204);
    browser.cookies.set("sid", sid!); // replaying the old cookie must not work
    expect((await me(browser)).status).toBe(401);
  });

  test("unknown user and wrong password produce the same generic error", async () => {
    const browser = new Browser();
    const username = await register(browser);
    const unknown = await browser.post("/api/auth/password/login", { username: "nobody-here", password: PASSWORD });
    const wrong = await browser.post("/api/auth/password/login", { username, password: "wrong password!!" });
    expect(unknown.status).toBe(401);
    expect(wrong.status).toBe(401);
    expect(await unknown.json()).toEqual(await wrong.json());
  });

  test("account locks after repeated failures, even for the correct password", async () => {
    const browser = new Browser();
    const username = await register(browser);
    for (let i = 0; i < config.lockout.maxFailedAttempts; i++) {
      await browser.post("/api/auth/password/login", { username, password: "wrong password!!" });
    }
    const locked = await browser.post("/api/auth/password/login", { username, password: PASSWORD });
    expect(locked.status).toBe(401);
  });

  test("sign out everywhere ends sessions in every browser", async () => {
    const laptop = new Browser();
    const username = await register(laptop);
    const phone = new Browser();
    await laptop.post("/api/auth/password/login", { username, password: PASSWORD });
    await phone.post("/api/auth/password/login", { username, password: PASSWORD });
    expect((await me(phone)).status).toBe(200);
    expect((await laptop.post("/api/me/logout-all")).status).toBe(204);
    expect((await me(phone)).status).toBe(401);
    expect((await me(laptop)).status).toBe(401);
  });

  test("passwords are never stored in plaintext", async () => {
    const browser = new Browser();
    const username = await register(browser);
    const user = await db.getRepository(User).findOneByOrFail({ username });
    expect(user.passwordHash).toStartWith("$argon2id$");
    expect(user.passwordHash).not.toContain(PASSWORD);
  });
});

describe("MFA (password + TOTP)", () => {
  async function enroll() {
    const browser = new Browser();
    const username = await register(browser);
    const step1 = await browser.post("/api/auth/mfa/login", { username, password: PASSWORD });
    const enrollment = (await step1.json()) as { status: string; secret: string; qrCodeDataUrl: string; otpauthUrl: string };
    expect(enrollment.status).toBe("enrollment_required");
    expect(enrollment.qrCodeDataUrl).toStartWith("data:image/png;base64,");
    expect(enrollment.otpauthUrl).toStartWith("otpauth://totp/");
    expect(browser.cookies.get("sid")).toBeUndefined(); // password alone grants nothing

    const verify = await browser.post("/api/auth/mfa/verify", { code: totpCode(enrollment.secret) });
    expect(verify.status).toBe(200);
    const body = (await verify.json()) as { recoveryCodes: string[] };
    expect(body.recoveryCodes).toHaveLength(config.mfa.recoveryCodeCount);
    expect((await me(browser)).body.auth.method).toBe("mfa");
    return { username, secret: enrollment.secret, recoveryCodes: body.recoveryCodes };
  }

  async function startMfaLogin(username: string) {
    const browser = new Browser();
    const response = await browser.post("/api/auth/mfa/login", { username, password: PASSWORD });
    expect(((await response.json()) as { status: string }).status).toBe("mfa_required");
    return browser;
  }

  test("enrollment stores the secret encrypted, never in plaintext", async () => {
    const { username, secret } = await enroll();
    const user = await db.getRepository(User).findOneByOrFail({ username });
    expect(user.mfaEnabled).toBe(true);
    expect(user.totpSecretEnc).toStartWith("v1.");
    expect(user.totpSecretEnc).not.toContain(secret);
  });

  test("password-only flows are refused once MFA is enabled", async () => {
    const { username } = await enroll();
    const browser = new Browser();
    expect((await browser.post("/api/auth/password/login", { username, password: PASSWORD })).status).toBe(403);
    expect((await browser.post("/api/auth/jwt/login", { username, password: PASSWORD })).status).toBe(403);
  });

  test("a TOTP code cannot be replayed", async () => {
    const { username, secret } = await enroll();
    const replayed = await startMfaLogin(username);
    // The enrollment code's time-step is already burned.
    expect((await replayed.post("/api/auth/mfa/verify", { code: totpCode(secret) })).status).toBe(401);
    const next = totpCode(secret, 1);
    expect((await replayed.post("/api/auth/mfa/verify", { code: next })).status).toBe(200);
    const again = await startMfaLogin(username);
    expect((await again.post("/api/auth/mfa/verify", { code: next })).status).toBe(401);
  });

  test("recovery codes work exactly once", async () => {
    const { username, recoveryCodes } = await enroll();
    const first = await startMfaLogin(username);
    expect((await first.post("/api/auth/mfa/verify", { code: recoveryCodes[0] })).status).toBe(200);
    const second = await startMfaLogin(username);
    expect((await second.post("/api/auth/mfa/verify", { code: recoveryCodes[0] })).status).toBe(401);
  });

  test("the challenge dies after too many wrong codes", async () => {
    const { username, secret } = await enroll();
    const browser = await startMfaLogin(username);
    let last: Response | undefined;
    for (let i = 0; i < config.mfa.maxAttempts; i++) last = await browser.post("/api/auth/mfa/verify", { code: "000000" });
    expect(((await last!.json()) as { error: string }).error).toBe("challenge_expired");
    const afterLimit = await browser.post("/api/auth/mfa/verify", { code: totpCode(secret, 1) });
    expect(afterLimit.status).toBe(401);
  });
});

describe("JWT (access + rotating refresh token)", () => {
  async function jwtLogin() {
    const browser = new Browser();
    const username = await register(browser);
    const response = await browser.post("/api/auth/jwt/login", { username, password: PASSWORD });
    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    const body = (await response.json()) as { accessToken: string; user: { id: string } };
    expect(browser.cookies.get("sid")).toBeUndefined();
    return { browser, accessToken: body.accessToken, userId: body.user.id };
  }

  test("bearer token authenticates; forged and alg=none tokens do not", async () => {
    const { browser, accessToken } = await jwtLogin();
    const ok = await me(browser, { authorization: `Bearer ${accessToken}` });
    expect(ok.status).toBe(200);
    expect(ok.body.auth.method).toBe("jwt");

    const [header, payload] = accessToken.split(".");
    const tampered = JSON.parse(Buffer.from(payload!, "base64url").toString());
    tampered.sub = "someone-else";
    const forged = `${header}.${Buffer.from(JSON.stringify(tampered)).toString("base64url")}.${accessToken.split(".")[2]}`;
    expect((await me(browser, { authorization: `Bearer ${forged}` })).status).toBe(401);

    const none = `${Buffer.from(JSON.stringify({ alg: "none", typ: "at+jwt" })).toString("base64url")}.${payload}.`;
    expect((await me(browser, { authorization: `Bearer ${none}` })).status).toBe(401);
  });

  test("refresh rotates; reusing a rotated token revokes the whole family", async () => {
    const { browser } = await jwtLogin();
    const original = browser.cookies.get("rt")!;
    const refreshed = await browser.post("/api/auth/jwt/refresh");
    expect(refreshed.status).toBe(200);
    const rotated = browser.cookies.get("rt")!;
    expect(rotated).not.toBe(original);

    browser.cookies.set("rt", original); // attacker replays the stolen, already-used token
    expect((await browser.post("/api/auth/jwt/refresh")).status).toBe(401);
    browser.cookies.set("rt", rotated); // the legitimate successor is now revoked as well
    expect((await browser.post("/api/auth/jwt/refresh")).status).toBe(401);
  });

  test("sign out everywhere revokes outstanding access tokens", async () => {
    const { browser, accessToken, userId } = await jwtLogin();
    const auth = { authorization: `Bearer ${accessToken}` };
    expect((await browser.post("/api/me/logout-all", undefined, auth)).status).toBe(204);
    expect((await me(browser, auth)).status).toBe(401);
    // A token minted with the old version (e.g. stolen earlier) is dead too.
    const stale = await signAccessToken(userId, 0);
    expect((await me(browser, { authorization: `Bearer ${stale.token}` })).status).toBe(401);
  });
});

describe("OAuth 2.0 authorization code + PKCE (mock DemoID provider)", () => {
  async function authorize(browser: Browser, decision: "allow" | "deny") {
    const start = await browser.get("/api/auth/oauth/demo/start");
    expect(start.status).toBe(302);
    const authorizeUrl = new URL(start.headers.get("location")!);
    expect(authorizeUrl.origin).toBe(PROVIDER);
    expect(authorizeUrl.searchParams.get("code_challenge_method")).toBe("S256");
    expect(authorizeUrl.searchParams.get("state")).toBe(browser.cookies.get("oauth_state")!);

    const consent = await browser.get(authorizeUrl.toString());
    const html = await consent.text();
    const transaction = /name="transaction" value="([^"]+)"/.exec(html)![1]!;
    const sub = /name="sub" value="([^"]+)"/.exec(html)![1]!;
    const decided = await browser.request("POST", `${PROVIDER}/authorize`, {
      form: { transaction, sub, decision },
      headers: { origin: PROVIDER },
    });
    expect(decided.status).toBe(303);
    return new URL(decided.headers.get("location")!);
  }

  test("full flow signs the user in and lands on the dashboard", async () => {
    const browser = new Browser();
    const callback = await authorize(browser, "allow");
    expect(callback.toString()).toStartWith(config.oauth.redirectUri);
    const done = await browser.get(callback.pathname + callback.search);
    expect(done.headers.get("location")).toBe(`${API}/dashboard`);
    expect((await me(browser)).body.auth.method).toBe("oauth");
  });

  test("callback with a state not bound to this browser is rejected (login CSRF)", async () => {
    const victim = new Browser();
    const attackerCallback = await authorize(new Browser(), "allow");
    const result = await victim.get(attackerCallback.pathname + attackerCallback.search);
    expect(result.headers.get("location")).toBe(`${API}/login/oauth?error=invalid_state`);
    expect((await me(victim)).status).toBe(401);
  });

  test("denied consent is reported without signing in", async () => {
    const browser = new Browser();
    const callback = await authorize(browser, "deny");
    const result = await browser.get(callback.pathname + callback.search);
    expect(result.headers.get("location")).toBe(`${API}/login/oauth?error=access_denied`);
  });

  test("provider enforces PKCE, single-use codes and exact redirect_uri", async () => {
    const browser = new Browser();
    const callback = await authorize(browser, "allow");
    const code = callback.searchParams.get("code")!;
    const basic = Buffer.from(`${config.oauth.clientId}:${encodeURIComponent(config.oauth.clientSecret)}`).toString("base64");
    const exchange = (verifier: string) =>
      fetch(`${PROVIDER}/token`, {
        method: "POST",
        headers: { authorization: `Basic ${basic}`, "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: config.oauth.redirectUri, code_verifier: verifier }),
      });
    // A stolen code is useless without the verifier, and the failed attempt consumes it.
    expect((await exchange("x".repeat(43))).status).toBe(400);
    expect((await exchange("x".repeat(43))).status).toBe(400);

    const badRedirect = await fetch(
      `${PROVIDER}/authorize?response_type=code&client_id=${config.oauth.clientId}&redirect_uri=https://evil.example/cb&state=s&code_challenge=${"a".repeat(43)}&code_challenge_method=S256`,
      { redirect: "manual" },
    );
    expect(badRedirect.status).toBe(400); // error page, never a redirect to the unregistered URI
  });
});
