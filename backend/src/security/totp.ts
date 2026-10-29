import { createHmac, randomBytes } from "node:crypto";
import { safeEqual } from "./crypto";

/** RFC 6238 TOTP (HMAC-SHA1, 30 s step, 6 digits): the parameters every authenticator app supports. */
const STEP_SECONDS = 30;
const DIGITS = 6;
const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function generateTotpSecret(): Buffer {
  return randomBytes(20); // 160 bits, the RFC 4226 recommended secret length
}

export function base32Encode(data: Buffer): string {
  let bits = 0;
  let value = 0;
  let output = "";
  for (const byte of data) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  return output;
}

/** RFC 4226 HOTP with dynamic truncation. */
export function hotp(secret: Buffer, counter: number, digits = DIGITS, algorithm = "sha1"): string {
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(BigInt(counter));
  const digest = createHmac(algorithm, secret).update(message).digest();
  const offset = digest[digest.length - 1]! & 0x0f;
  const binary = digest.readUInt32BE(offset) & 0x7fffffff;
  return (binary % 10 ** digits).toString().padStart(digits, "0");
}

export function timeStep(nowMs = Date.now()): number {
  return Math.floor(nowMs / 1000 / STEP_SECONDS);
}

/**
 * Accepts codes from the current step ±`window` steps (clock drift tolerance).
 * Steps at or before `lastUsedStep` are refused so a code cannot be replayed.
 * Returns the matched step (persist it as the new lastUsedStep) or null.
 */
export function verifyTotp(
  secret: Buffer,
  code: string,
  options: { lastUsedStep?: number | null; window?: number; nowMs?: number } = {},
): number | null {
  if (!/^\d{6}$/.test(code)) return null;
  const window = options.window ?? 1;
  const current = timeStep(options.nowMs);
  let matched: number | null = null;
  // Check every candidate step without returning early, to keep timing independent of which step matched.
  for (let step = current - window; step <= current + window; step++) {
    if (safeEqual(hotp(secret, step), code) && matched === null) matched = step;
  }
  if (matched === null) return null;
  if (options.lastUsedStep != null && matched <= options.lastUsedStep) return null;
  return matched;
}

export function otpauthUrl(issuer: string, account: string, secret: Buffer): string {
  const label = encodeURIComponent(`${issuer}:${account}`);
  const params = new URLSearchParams({
    secret: base32Encode(secret),
    issuer,
    algorithm: "SHA1",
    digits: String(DIGITS),
    period: String(STEP_SECONDS),
  });
  return `otpauth://totp/${label}?${params}`;
}
