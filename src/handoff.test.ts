import { describe, expect, it } from "vitest";
import { HandoffError, signHandoff, verifyHandoff } from "./handoff.js";
import type { EntraProfile } from "./types.js";

const secret = "handoff-secret-please-do-not-reuse-1234567890";

const profile: EntraProfile = {
  email: "morten@godtbrod.no",
  displayName: "Morten M",
  jobTitle: "Baker",
  officeLocation: "12 Grünerløkka",
  raw: { oid: "abc-123" },
};

const targetHost = "pr-42-deigverkstedet.apps.gb.logiskbrist.no";

describe("handoff JWT", () => {
  it("roundtrips a valid token", () => {
    const token = signHandoff(
      { profile, targetHost, returnTo: "/", ttlSeconds: 60 },
      secret,
    );
    const payload = verifyHandoff({ token, expectedTargetHost: targetHost }, secret);
    expect(payload.profile.email).toBe(profile.email);
    expect(payload.targetHost).toBe(targetHost);
    expect(payload.returnTo).toBe("/");
  });

  it("rejects a token signed with a different secret", () => {
    const token = signHandoff(
      { profile, targetHost, returnTo: "/", ttlSeconds: 60 },
      secret,
    );
    expect(() =>
      verifyHandoff({ token, expectedTargetHost: targetHost }, "other-secret"),
    ).toThrow(HandoffError);
  });

  it("rejects tampered payload", () => {
    const token = signHandoff(
      { profile, targetHost, returnTo: "/", ttlSeconds: 60 },
      secret,
    );
    const [h, p, s] = token.split(".") as [string, string, string];
    // Flip the last char of the payload.
    const swap = p.slice(0, -1) + (p.endsWith("A") ? "B" : "A");
    const tampered = `${h}.${swap}.${s}`;
    expect(() =>
      verifyHandoff({ token: tampered, expectedTargetHost: targetHost }, secret),
    ).toThrow(HandoffError);
  });

  it("rejects an expired token", () => {
    const t0 = 1_700_000_000_000;
    const token = signHandoff(
      { profile, targetHost, returnTo: "/", ttlSeconds: 60, now: () => t0 },
      secret,
    );
    expect(() =>
      verifyHandoff(
        { token, expectedTargetHost: targetHost, now: () => t0 + 61_000 },
        secret,
      ),
    ).toThrow(/expired/);
  });

  it("rejects when target host differs", () => {
    const token = signHandoff(
      { profile, targetHost, returnTo: "/", ttlSeconds: 60 },
      secret,
    );
    expect(() =>
      verifyHandoff(
        { token, expectedTargetHost: "attacker.example.com" },
        secret,
      ),
    ).toThrow(/host_mismatch|does not match/);
  });

  it("rejects replays via markNonceUsed", () => {
    const token = signHandoff(
      { profile, targetHost, returnTo: "/", ttlSeconds: 60 },
      secret,
    );
    const seen = new Set<string>();
    const mark = (n: string) => {
      if (seen.has(n)) return false;
      seen.add(n);
      return true;
    };
    verifyHandoff(
      { token, expectedTargetHost: targetHost, markNonceUsed: mark },
      secret,
    );
    expect(() =>
      verifyHandoff(
        { token, expectedTargetHost: targetHost, markNonceUsed: mark },
        secret,
      ),
    ).toThrow(/replay|already used/);
  });

  it("rejects malformed input", () => {
    expect(() =>
      verifyHandoff({ token: "not-a-jwt", expectedTargetHost: targetHost }, secret),
    ).toThrow(HandoffError);
  });
});
