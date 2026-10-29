/**
 * Creates backend/.env with freshly generated random secrets if it does not exist yet.
 * Secrets must stay stable across restarts: rotating ENCRYPTION_KEY makes stored TOTP
 * secrets unreadable and rotating PASSWORD_PEPPER invalidates every password hash.
 */
import { randomBytes } from "node:crypto";
import path from "node:path";

const envPath = path.join(import.meta.dir, "..", ".env");
const examplePath = path.join(import.meta.dir, "..", ".env.example");

if (await Bun.file(envPath).exists()) process.exit(0);

const template = await Bun.file(examplePath).text();
const generated = template.replace(/^([A-Z_]+)=__GENERATE__$/gm, (_, name: string) => {
  return `${name}=${randomBytes(32).toString("base64")}`;
});

await Bun.write(envPath, generated);
console.log(`Generated ${path.relative(process.cwd(), envPath)} with random secrets.`);
