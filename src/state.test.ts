import { describe, expect, it } from "vitest";
import { decryptState, encryptState, safeStringEqual, StateError } from "./state.js";

const secret = "test-secret-that-is-not-a-real-one-1234567890";

const payload = {
  csrf: "csrf-token-abc",
  codeVerifier: "verifier-string-1234567890",
  targetHost: "pr-42-deigverkstedet.apps.gb.logiskbrist.no",
  returnTo: "/some/path",
};

describe("state", () => {
  it("roundtrips a payload", () => {
    const token = encryptState(payload, secret);
    const out = decryptState(token, secret, { ttlSeconds: 60 });
    expect(out.csrf).toBe(payload.csrf);
    expect(out.codeVerifier).toBe(payload.codeVerifier);
    expect(out.targetHost).toBe(payload.targetHost);
    expect(out.returnTo).toBe(payload.returnTo);
    expect(typeof out.iat).toBe("number");
  });

  it("rejects tokens signed with a different secret", () => {
    const token = encryptState(payload, secret);
    expect(() =>
      decryptState(token, "different-secret", { ttlSeconds: 60 }),
    ).toThrow(StateError);
  });

  it("rejects tampered ciphertext", () => {
    const token = encryptState(payload, secret);
    const bad = token.slice(0, -4) + "AAAA";
    expect(() => decryptState(bad, secret, { ttlSeconds: 60 })).toThrow(
      StateError,
    );
  });

  it("rejects expired state", () => {
    const t0 = 1_700_000_000_000;
    const token = encryptState(payload, secret, { now: () => t0 });
    // 61 s later — outside a 60 s TTL
    expect(() =>
      decryptState(token, secret, {
        ttlSeconds: 60,
        now: () => t0 + 61_000,
      }),
    ).toThrow(/expired/);
  });

  it("rejects state issued in the future", () => {
    const t0 = 1_700_000_000_000;
    const token = encryptState(payload, secret, { now: () => t0 });
    // Verifier clock is 120 s BEHIND signer's — bigger than the 60 s window we allow.
    expect(() =>
      decryptState(token, secret, {
        ttlSeconds: 600,
        now: () => t0 - 120_000,
      }),
    ).toThrow(/future/);
  });

  it("rejects malformed input", () => {
    expect(() =>
      decryptState("not-a-real-token", secret, { ttlSeconds: 60 }),
    ).toThrow(StateError);
  });
});

describe("safeStringEqual", () => {
  it("compares equal strings", () => {
    expect(safeStringEqual("abc", "abc")).toBe(true);
  });

  it("rejects unequal strings", () => {
    expect(safeStringEqual("abc", "abd")).toBe(false);
  });

  it("rejects unequal lengths without leaking timing", () => {
    expect(safeStringEqual("abc", "abcd")).toBe(false);
  });
});
