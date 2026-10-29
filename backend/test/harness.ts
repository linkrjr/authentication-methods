import type { Server } from "node:http";
import type { Express } from "express";
import { createApp } from "../src/app";
import { config } from "../src/config";
import { db } from "../src/db";
import { createOAuthProvider } from "../src/oauth-provider/server";
import { hotp, timeStep } from "../src/security/totp";

export const API = config.appOrigin;
export const PROVIDER = config.oauth.providerUrl;

let servers: Server[] = [];

function listen(app: Express, port: number): Promise<Server> {
  const { promise, resolve } = Promise.withResolvers<Server>();
  const server = app.listen(port, () => resolve(server));
  return promise;
}

export async function startServers() {
  if (!db.isInitialized) await db.initialize();
  servers = [await listen(createApp(), config.port), await listen(createOAuthProvider(), config.oauth.providerPort)];
}

export async function stopServers() {
  await Promise.all(servers.map((server) => server.close()));
}

/** Minimal browser stand-in: cookie jar, same-origin Origin header, CSRF token, manual redirects. */
export class Browser {
  readonly cookies = new Map<string, string>();
  readonly setCookieHeaders: string[] = [];
  private csrf: string | null = null;

  async request(method: string, url: string, init: { body?: unknown; headers?: Record<string, string>; form?: Record<string, string> } = {}) {
    const absolute = url.startsWith("http") ? url : `${API}${url}`;
    const headers: Record<string, string> = { ...init.headers };
    if (this.cookies.size && absolute.startsWith(API)) {
      headers.cookie = [...this.cookies].map(([name, value]) => `${name}=${value}`).join("; ");
    }
    let body: string | undefined;
    if (init.form) {
      body = new URLSearchParams(init.form).toString();
      headers["content-type"] = "application/x-www-form-urlencoded";
    } else if (init.body !== undefined) {
      body = JSON.stringify(init.body);
      headers["content-type"] = "application/json";
    }
    const response = await fetch(absolute, { method, headers, body, redirect: "manual" });
    if (absolute.startsWith(API)) {
      for (const header of response.headers.getSetCookie()) {
        this.setCookieHeaders.push(header);
        const [pair = ""] = header.split(";");
        const [name = "", ...rest] = pair.split("=");
        const value = rest.join("=");
        if (!value || /max-age=0|expires=thu, 01 jan 1970/i.test(header)) this.cookies.delete(name);
        else this.cookies.set(name, value);
      }
    }
    return response;
  }

  async get(url: string, headers?: Record<string, string>) {
    return this.request("GET", url, { headers });
  }

  /** Same-origin state-changing request, like the SPA sends. */
  async post(url: string, body?: unknown, headers: Record<string, string> = {}) {
    if (!this.csrf) {
      const csrfResponse = (await (await this.get("/api/auth/csrf")).json()) as { csrfToken: string };
      const { csrfToken } = csrfResponse;
      this.csrf = csrfToken;
    }
    return this.request("POST", url, { body, headers: { origin: API, "x-csrf-token": this.csrf, ...headers } });
  }
}

export function base32Decode(input: string): Buffer {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0;
  let value = 0;
  const bytes: number[] = [];
  for (const char of input) {
    value = (value << 5) | alphabet.indexOf(char);
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

export function totpCode(base32Secret: string, stepOffset = 0): string {
  return hotp(base32Decode(base32Secret), timeStep() + stepOffset);
}

let counter = 0;
export const uniqueName = (prefix: string) => `${prefix}${Date.now().toString(36)}${counter++}`;
export const PASSWORD = "correct horse battery staple";
