import express from "express";
import { describe, expect, it, vi } from "vitest";
import request from "supertest";
import { mountEntraAuth } from "./mount.js";
import { encryptState } from "./state.js";
import type { AuthErrorInfo, MsalLike } from "./types.js";

const secret = "onerror-secret-0000000000000000000000000000000000";
const otherSecret = "different-secret-0000000000000000000000000000000000";

function makeMsal(fail?: "start" | "token"): MsalLike {
  return {
    async getAuthCodeUrl(input) {
      if (fail === "start") throw new Error("boom");
      return `https://login.microsoftonline.com/tid/authorize?state=${encodeURIComponent(
        input.state,
      )}`;
    },
    async acquireTokenByCode() {
      if (fail === "token") throw new Error("token boom");
      return {
        idTokenClaims: { email: "u@godtbrod.no", name: "u" },
        accessToken: "at",
      };
    },
  };
}

function buildApp(opts: {
  onError?: (i: AuthErrorInfo, r: express.Request) => string | undefined | void;
  msalFail?: "start" | "token";
  prodAuthOrigin?: string;
}) {
  const app = express();
  app.set("trust proxy", 1);
  mountEntraAuth(app, {
    tenantId: "t",
    clientId: "c",
    clientSecret: "s",
    redirectUri: "https://foo.apps.gb.logiskbrist.no/api/auth/microsoft/callback",
    prodAuthOrigin: opts.prodAuthOrigin,
    handoffSecret: secret,
    onLogin: async () => undefined,
    msalClient: makeMsal(opts.msalFail),
    onError: opts.onError,
  });
  return app;
}

describe("mountEntraAuth — onError", () => {
  it("redirects on target_origin_denied when onError returns a URL", async () => {
    const capture: AuthErrorInfo[] = [];
    const app = buildApp({
      onError: (i) => {
        capture.push(i);
        return "/auth/login?feil=ugyldig";
      },
    });
    const res = await request(app)
      .get("/api/auth/microsoft/login")
      .query({ target: "https://evil.example.com" })
      .set("Host", "foo.apps.gb.logiskbrist.no")
      .set("X-Forwarded-Proto", "https");
    expect(res.status).toBe(302);
    expect(res.headers.location).toBe("/auth/login?feil=ugyldig");
    expect(capture[0]?.code).toBe("target_origin_denied");
    expect(capture[0]?.step).toBe("login");
  });

  it("falls back to default 400 body when onError returns void", async () => {
    const app = buildApp({ onError: () => undefined });
    const res = await request(app)
      .get("/api/auth/microsoft/login")
      .query({ target: "https://evil.example.com" })
      .set("Host", "foo.apps.gb.logiskbrist.no")
      .set("X-Forwarded-Proto", "https");
    expect(res.status).toBe(400);
    expect(res.text).toContain("target");
  });

  it("routes Entra error params through onError with structured info", async () => {
    const capture: AuthErrorInfo[] = [];
    const app = buildApp({
      onError: (i) => {
        capture.push(i);
        return "/auth/login?feil=konto";
      },
    });
    const res = await request(app)
      .get("/api/auth/microsoft/callback")
      .query({
        error: "access_denied",
        error_description: "User canceled",
      })
      .set("Host", "foo.apps.gb.logiskbrist.no")
      .set("X-Forwarded-Proto", "https");
    expect(res.status).toBe(302);
    expect(res.headers.location).toBe("/auth/login?feil=konto");
    expect(capture[0]?.code).toBe("entra_denied");
    expect(capture[0]?.entraError).toBe("access_denied");
    expect(capture[0]?.entraDescription).toBe("User canceled");
  });

  it("routes handoff errors through onError with handoff_ prefix", async () => {
    const capture: AuthErrorInfo[] = [];
    const app = express();
    app.set("trust proxy", 1);
    mountEntraAuth(app, {
      tenantId: "t",
      clientId: "c",
      clientSecret: "s",
      redirectUri: "https://foo.apps.gb.logiskbrist.no/api/auth/microsoft/callback",
      prodAuthOrigin: "https://foo.apps.gb.logiskbrist.no",
      handoffSecret: secret,
      onLogin: async () => undefined,
      msalClient: makeMsal(),
      onError: (i) => {
        capture.push(i);
        return "/auth/login?feil=ugyldig";
      },
    });
    // A garbage handoff token → verifyHandoff throws HandoffError malformed.
    const res = await request(app)
      .get("/api/auth/microsoft/handoff")
      .query({ t: "abc.def.ghi" })
      .set("Host", "pr-5-foo.apps.gb.logiskbrist.no")
      .set("X-Forwarded-Proto", "https");
    expect(res.status).toBe(302);
    expect(res.headers.location).toBe("/auth/login?feil=ugyldig");
    expect(capture[0]?.step).toBe("handoff");
    expect(capture[0]?.code).toMatch(/^handoff_/);
  });

  it("routes state_expired through onError with the right code", async () => {
    const capture: AuthErrorInfo[] = [];
    const app = buildApp({
      onError: (i) => {
        capture.push(i);
        return "/auth/login?feil=ugyldig";
      },
    });
    // State encrypted with the wrong key — decryptState throws StateError("tampered").
    const state = encryptState(
      {
        csrf: "c",
        codeVerifier: "v",
        targetHost: "foo.apps.gb.logiskbrist.no",
        returnTo: "/",
      },
      otherSecret,
    );
    const res = await request(app)
      .get("/api/auth/microsoft/callback")
      .query({ code: "x", state })
      .set("Host", "foo.apps.gb.logiskbrist.no")
      .set("X-Forwarded-Proto", "https");
    expect(res.status).toBe(302);
    expect(capture[0]?.step).toBe("callback");
    expect(capture[0]?.code).toBe("state_tampered");
  });

  it("shrugs off an onError that itself throws — falls back to default 400", async () => {
    const app = buildApp({
      onError: () => {
        throw new Error("onError itself broken");
      },
    });
    const res = await request(app)
      .get("/api/auth/microsoft/login")
      .query({ target: "https://evil.example.com" })
      .set("Host", "foo.apps.gb.logiskbrist.no")
      .set("X-Forwarded-Proto", "https");
    expect(res.status).toBe(400);
  });
});
