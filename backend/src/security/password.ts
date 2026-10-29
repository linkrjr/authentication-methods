import { createHmac } from "node:crypto";
import { config } from "../config";

/**
 * Password storage:
 *  1. NFKC-normalize so visually identical Unicode input hashes identically.
 *  2. HMAC-SHA256 with a server-side "pepper" kept outside the database: a stolen DB
 *     alone is not enough to run an offline guessing attack.
 *  3. argon2id (memory-hard, OWASP/RFC 9106 recommended). Bun generates a fresh random
 *     32-byte salt per hash and stores it inside the PHC string, so identical passwords
 *     never produce identical hashes and precomputed (rainbow) tables are useless.
 *     Example: $argon2id$v=19$m=65536,t=3,p=1$<salt>$<digest>
 */
const ARGON2 = { algorithm: "argon2id", memoryCost: 65536, timeCost: 3 } as const;
const CURRENT_PARAMS = `$argon2id$v=19$m=${ARGON2.memoryCost},t=${ARGON2.timeCost},p=1$`;

function pepper(password: string): string {
  return createHmac("sha256", config.secrets.passwordPepper).update(password.normalize("NFKC")).digest("base64");
}

export function hashPassword(password: string): Promise<string> {
  return Bun.password.hash(pepper(password), ARGON2);
}

export function verifyPassword(password: string, hash: string): Promise<boolean> {
  return Bun.password.verify(pepper(password), hash);
}

/** True when the stored hash was produced with older cost parameters and should be upgraded on next login. */
export function needsRehash(hash: string): boolean {
  return !hash.startsWith(CURRENT_PARAMS);
}

let dummyHash: Promise<string> | undefined;

/**
 * Burn the same CPU/memory as a real verification when the user does not exist (or has no
 * password), so response timing does not reveal which usernames are registered.
 */
export async function verifyAgainstDummy(password: string): Promise<false> {
  dummyHash ??= hashPassword("dummy-password-for-timing-equalization");
  await verifyPassword(password, await dummyHash);
  return false;
}
