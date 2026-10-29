import { describe, expect, test } from "bun:test";
import { config } from "../src/config";
import { decrypt, encrypt } from "../src/security/crypto";
import { hashPassword, needsRehash, verifyPassword } from "../src/security/password";
import { base32Encode, hotp, verifyTotp } from "../src/security/totp";

describe("password hashing", () => {
  test("argon2id with a unique random salt per hash", async () => {
    const [a, b] = await Promise.all([hashPassword("same password here"), hashPassword("same password here")]);
    expect(a).toStartWith("$argon2id$v=19$m=65536,t=3,p=1$");
    expect(a).not.toBe(b); // different salts
    expect(a.split("$")[4]).not.toBe(b.split("$")[4]);
    expect(await verifyPassword("same password here", a)).toBe(true);
    expect(await verifyPassword("same password herE", a)).toBe(false);
    expect(needsRehash(a)).toBe(false);
  });

  test("Unicode-equivalent passwords verify identically (NFKC)", async () => {
    const hash = await hashPassword("ﬁve-ligature-pass");
    expect(await verifyPassword("five-ligature-pass", hash)).toBe(true);
  });

  test("hash is peppered: plain argon2id of the password does not verify", async () => {
    const hash = await hashPassword("peppered password");
    expect(await Bun.password.verify("peppered password", hash)).toBe(false);
  });

  test("hashes with weaker parameters are flagged for rehash", async () => {
    expect(needsRehash(await Bun.password.hash("x", { algorithm: "argon2id", memoryCost: 4096, timeCost: 1 }))).toBe(true);
  });
});

describe("TOTP", () => {
  // RFC 6238 Appendix B test vectors (SHA-1, 8 digits).
  const secret = Buffer.from("12345678901234567890");
  test.each([
    [59, "94287082"],
    [1111111109, "07081804"],
    [1111111111, "14050471"],
    [1234567890, "89005924"],
    [2000000000, "69279037"],
    [20000000000, "65353130"],
  ])("RFC 6238 vector at T=%d", (seconds, expected) => {
    expect(hotp(secret, Math.floor(seconds / 30), 8)).toBe(expected);
  });

  test("base32 matches RFC 4648", () => {
    expect(base32Encode(secret)).toBe("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
  });

  test("accepts ±1 step of drift, rejects older codes and replays", () => {
    const nowMs = 1_700_000_000_000;
    const step = Math.floor(nowMs / 30_000);
    expect(verifyTotp(secret, hotp(secret, step - 1), { nowMs })).toBe(step - 1);
    expect(verifyTotp(secret, hotp(secret, step + 1), { nowMs })).toBe(step + 1);
    expect(verifyTotp(secret, hotp(secret, step - 2), { nowMs })).toBeNull();
    expect(verifyTotp(secret, hotp(secret, step), { nowMs, lastUsedStep: step })).toBeNull();
    expect(verifyTotp(secret, "12345", { nowMs })).toBeNull();
  });
});

describe("AES-256-GCM", () => {
  const key = config.secrets.encryptionKey;

  test("round-trips and uses a fresh IV each time", () => {
    const a = encrypt(key, Buffer.from("secret"), "totp:user-1");
    expect(a).not.toBe(encrypt(key, Buffer.from("secret"), "totp:user-1"));
    expect(decrypt(key, a, "totp:user-1").toString()).toBe("secret");
  });

  test("ciphertext is bound to its owner (AAD) and tamper-evident", () => {
    const sealed = encrypt(key, Buffer.from("secret"), "totp:user-1");
    expect(() => decrypt(key, sealed, "totp:user-2")).toThrow();
    const [v, iv, ct, tag] = sealed.split(".");
    const flipped = Buffer.from(ct!, "base64url");
    flipped[0]! ^= 1;
    expect(() => decrypt(key, [v, iv, flipped.toString("base64url"), tag].join("."), "totp:user-1")).toThrow();
  });
});
