import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";
import type { StatePayload } from "./types.js";

const ALG = "aes-256-gcm";
const IV_LEN = 12;
const TAG_LEN = 16;

function b64urlEncode(buf: Buffer): string {
  return buf.toString("base64url");
}

function b64urlDecode(s: string): Buffer {
  return Buffer.from(s, "base64url");
}

function deriveKey(secret: string): Buffer {
  return createHash("sha256").update(secret, "utf8").digest();
}

export interface EncryptOptions {
  now?: () => number;
}

export function encryptState(
  payload: Omit<StatePayload, "iat">,
  secret: string,
  opts: EncryptOptions = {},
): string {
  const now = opts.now ? opts.now() : Date.now();
  const full: StatePayload = { ...payload, iat: Math.floor(now / 1000) };
  const key = deriveKey(secret);
  const iv = randomBytes(IV_LEN);
  const cipher = createCipheriv(ALG, key, iv);
  const plaintext = Buffer.from(JSON.stringify(full), "utf8");
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return b64urlEncode(Buffer.concat([iv, tag, ciphertext]));
}

export interface DecryptOptions {
  ttlSeconds: number;
  now?: () => number;
}

export class StateError extends Error {
  constructor(
    message: string,
    public code:
      | "malformed"
      | "tampered"
      | "expired"
      | "wrong_key",
  ) {
    super(message);
    this.name = "StateError";
  }
}

export function decryptState(
  token: string,
  secret: string,
  opts: DecryptOptions,
): StatePayload {
  const buf = b64urlDecode(token);
  if (buf.length < IV_LEN + TAG_LEN + 1) {
    throw new StateError("state too short", "malformed");
  }
  const iv = buf.subarray(0, IV_LEN);
  const tag = buf.subarray(IV_LEN, IV_LEN + TAG_LEN);
  const ct = buf.subarray(IV_LEN + TAG_LEN);
  const key = deriveKey(secret);
  const decipher = createDecipheriv(ALG, key, iv);
  decipher.setAuthTag(tag);
  let plaintext: Buffer;
  try {
    plaintext = Buffer.concat([decipher.update(ct), decipher.final()]);
  } catch {
    throw new StateError("state auth-tag mismatch", "tampered");
  }
  let parsed: StatePayload;
  try {
    parsed = JSON.parse(plaintext.toString("utf8")) as StatePayload;
  } catch {
    throw new StateError("state payload not JSON", "malformed");
  }
  if (
    typeof parsed.csrf !== "string" ||
    typeof parsed.codeVerifier !== "string" ||
    typeof parsed.targetHost !== "string" ||
    typeof parsed.returnTo !== "string" ||
    typeof parsed.iat !== "number"
  ) {
    throw new StateError("state payload shape wrong", "malformed");
  }
  const now = opts.now ? opts.now() : Date.now();
  const nowSec = Math.floor(now / 1000);
  if (nowSec - parsed.iat > opts.ttlSeconds) {
    throw new StateError("state expired", "expired");
  }
  if (parsed.iat - nowSec > 60) {
    throw new StateError("state issued in the future", "malformed");
  }
  return parsed;
}

/** Constant-time string compare, false when lengths differ. */
export function safeStringEqual(a: string, b: string): boolean {
  const aBuf = Buffer.from(a, "utf8");
  const bBuf = Buffer.from(b, "utf8");
  if (aBuf.length !== bBuf.length) return false;
  return timingSafeEqual(aBuf, bBuf);
}
