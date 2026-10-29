import { LessThan } from "typeorm";
import { createApp } from "./app";
import { config } from "./config";
import { db } from "./db";
import { MfaChallenge, OAuthState, RefreshToken, Session } from "./db/entities";
import { createOAuthProvider } from "./oauth-provider/server";

await db.initialize();

/** Housekeeping: expired credentials are useless but should not linger in the database. */
async function purgeExpired() {
  const now = new Date();
  await Promise.all([
    db.getRepository(Session).delete({ expiresAt: LessThan(now) }),
    db.getRepository(RefreshToken).delete({ expiresAt: LessThan(now) }),
    db.getRepository(MfaChallenge).delete({ expiresAt: LessThan(now) }),
    db.getRepository(OAuthState).delete({ expiresAt: LessThan(now) }),
  ]);
}
await purgeExpired();
setInterval(() => purgeExpired().catch(console.error), 10 * 60 * 1000).unref();

createApp().listen(config.port, () => {
  console.log(`API          http://localhost:${config.port}  (web app origin ${config.appOrigin})`);
});
createOAuthProvider().listen(config.oauth.providerPort, () => {
  console.log(`Mock OAuth   ${config.oauth.providerUrl}  (DemoID authorization server)`);
});
