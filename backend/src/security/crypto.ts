import { createCipheriv, createDecipheriv, createHash, randomBytes, timingSafeEqual } from "node:crypto";

/** 256-bit CSPRNG token, URL-safe. */
export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString("base64url");
}

/** Tokens are stored as SHA-256 digests so a database leak does not yield usable sessions/tokens. */
export function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

/** Constant-time string comparison (length is not secret here: all compared values are fixed-size). */
export function safeEqual(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}

const VERSION = "v1";

/**
 * AES-256-GCM authenticated encryption. `aad` binds the ciphertext to its context
 * (e.g. the owning user id), so a ciphertext copied onto another row fails to decrypt.
 * Format: v1.<iv>.<ciphertext>.<tag> (base64url).
 */
export function encrypt(key: Buffer, plaintext: Buffer, aad: string): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(Buffer.from(aad));
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return [VERSION, iv, ciphertext, tag].map((part) => (typeof part === "string" ? part : part.toString("base64url"))).join(".");
}

export function decrypt(key: Buffer, payload: string, aad: string): Buffer {
  const [version, iv, ciphertext, tag] = payload.split(".");
  if (version !== VERSION || !iv || !ciphertext || !tag) throw new Error("Unsupported ciphertext format");
  const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(iv, "base64url"));
  decipher.setAAD(Buffer.from(aad));
  decipher.setAuthTag(Buffer.from(tag, "base64url"));
  return Buffer.concat([decipher.update(Buffer.from(ciphertext, "base64url")), decipher.final()]);
}
