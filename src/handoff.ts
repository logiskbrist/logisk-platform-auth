import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import type { HandoffPayload } from "./types.js";

const ALG = "HS256";

function b64urlEncode(buf: Buffer | string): string {
  return Buffer.from(buf).toString("base64url");
}

function b64urlDecode(s: string): Buffer {
  return Buffer.from(s, "base64url");
}

function sign(headerB64: string, payloadB64: string, secret: string): string {
  const mac = createHmac("sha256", secret);
  mac.update(`${headerB64}.${payloadB64}`);
  return mac.digest("base64url");
}

export class HandoffError extends Error {
  constructor(
    message: string,
    public code:
      | "malformed"
      | "bad_signature"
      | "expired"
      | "host_mismatch"
      | "replay",
  ) {
    super(message);
    this.name = "HandoffError";
  }
}

export interface SignInput {
  profile: HandoffPayload["profile"];
  targetHost: string;
  returnTo: string;
  ttlSeconds: number;
  now?: () => number;
  nonce?: string;
}

export function signHandoff(input: SignInput, secret: string): string {
  const now = input.now ? input.now() : Date.now();
  const iat = Math.floor(now / 1000);
  const exp = iat + input.ttlSeconds;
  const payload: HandoffPayload = {
    profile: input.profile,
    targetHost: input.targetHost,
    returnTo: input.returnTo,
    nonce: input.nonce ?? randomBytes(16).toString("base64url"),
    iat,
    exp,
  };
  const headerB64 = b64urlEncode(JSON.stringify({ alg: ALG, typ: "JWT" }));
  const payloadB64 = b64urlEncode(JSON.stringify(payload));
  const sig = sign(headerB64, payloadB64, secret);
  return `${headerB64}.${payloadB64}.${sig}`;
}

export interface VerifyInput {
  token: string;
  expectedTargetHost: string;
  now?: () => number;
  markNonceUsed?: (nonce: string, ttlSeconds: number) => boolean;
}

export function verifyHandoff(input: VerifyInput, secret: string): HandoffPayload {
  const parts = input.token.split(".");
  if (parts.length !== 3) {
    throw new HandoffError("token must have 3 parts", "malformed");
  }
  const [headerB64, payloadB64, sigB64] = parts as [string, string, string];
  const expected = sign(headerB64, payloadB64, secret);
  const a = Buffer.from(expected, "utf8");
  const b = Buffer.from(sigB64, "utf8");
  if (a.length !== b.length || !timingSafeEqual(a, b)) {
    throw new HandoffError("signature mismatch", "bad_signature");
  }
  let payload: HandoffPayload;
  try {
    payload = JSON.parse(b64urlDecode(payloadB64).toString("utf8")) as HandoffPayload;
  } catch {
    throw new HandoffError("payload not JSON", "malformed");
  }
  if (
    typeof payload.targetHost !== "string" ||
    typeof payload.returnTo !== "string" ||
    typeof payload.nonce !== "string" ||
    typeof payload.exp !== "number" ||
    typeof payload.iat !== "number" ||
    typeof payload.profile?.email !== "string"
  ) {
    throw new HandoffError("payload shape wrong", "malformed");
  }
  const now = input.now ? input.now() : Date.now();
  const nowSec = Math.floor(now / 1000);
  if (nowSec >= payload.exp) {
    throw new HandoffError("token expired", "expired");
  }
  if (payload.targetHost !== input.expectedTargetHost) {
    throw new HandoffError(
      `target host ${payload.targetHost} does not match ${input.expectedTargetHost}`,
      "host_mismatch",
    );
  }
  if (input.markNonceUsed) {
    const ttl = payload.exp - nowSec;
    const first = input.markNonceUsed(payload.nonce, ttl);
    if (!first) throw new HandoffError("nonce already used", "replay");
  }
  return payload;
}
