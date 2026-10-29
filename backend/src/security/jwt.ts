import { SignJWT, jwtVerify } from "jose";
import { config } from "../config";
import { randomToken } from "./crypto";

const ALGORITHM = "HS256";
/** RFC 9068 access-token type; prevents other JWTs signed with the same key being accepted as access tokens. */
const TOKEN_TYPE = "at+jwt";

export interface AccessTokenClaims {
  sub: string;
  ver: number;
  exp: number;
}

export async function signAccessToken(userId: string, tokenVersion: number): Promise<{ token: string; expiresAt: Date }> {
  const now = Math.floor(Date.now() / 1000);
  const exp = now + config.jwt.accessTokenTtlSeconds;
  const token = await new SignJWT({ ver: tokenVersion, amr: ["pwd"] })
    .setProtectedHeader({ alg: ALGORITHM, typ: TOKEN_TYPE })
    .setSubject(userId)
    .setIssuer(config.jwt.issuer)
    .setAudience(config.jwt.audience)
    .setIssuedAt(now)
    .setNotBefore(now)
    .setExpirationTime(exp)
    .setJti(randomToken(16))
    .sign(config.secrets.jwtSecret);
  return { token, expiresAt: new Date(exp * 1000) };
}

/**
 * Pins the algorithm (blocks `alg: none` and HS/RS confusion), issuer, audience and token type,
 * and requires exp. Throws on any failure.
 */
export async function verifyAccessToken(token: string): Promise<AccessTokenClaims> {
  const { payload } = await jwtVerify(token, config.secrets.jwtSecret, {
    algorithms: [ALGORITHM],
    issuer: config.jwt.issuer,
    audience: config.jwt.audience,
    typ: TOKEN_TYPE,
    requiredClaims: ["sub", "exp", "iat", "jti"],
    clockTolerance: 5,
  });
  if (typeof payload.sub !== "string" || typeof payload.ver !== "number" || typeof payload.exp !== "number") {
    throw new Error("Malformed access token claims");
  }
  return { sub: payload.sub, ver: payload.ver, exp: payload.exp };
}
