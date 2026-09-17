import express from "express";
import { describe, expect, it, vi } from "vitest";
import request from "supertest";
import { mountEntraAuth } from "./mount.js";
import { encryptState } from "./state.js";
import type { EntraProfile, MsalLike } from "./types.js";

const secret = "test-handoff-secret-do-not-use-in-prod-000000";

function makeMsal(): MsalLike & {
  lastAuthCodeUrl?: Parameters<MsalLike["getAuthCodeUrl"]>[0];
  lastAcquire?: Parameters<MsalLike["acquireTokenByCode"]>[0];
} {
  const m: MsalLike & {
    lastAuthCodeUrl?: Parameters<MsalLike["getAuthCodeUrl"]>[0];
    lastAcquire?: Parameters<MsalLike["acquireTokenByCode"]>[0];
  } = {
    async getAuthCodeUrl(input) {
      m.lastAuthCodeUrl = input;
      const u = new URL("https://login.microsoftonline.com/tid/oauth2/v2.0/authorize");
      u.searchParams.set("state", input.state);
      u.searchParams.set("redirect_uri", input.redirectUri);
      return u.toString();
    },
    async acquireTokenByCode(input) {
      m.lastAcquire = input;
      return {
        idTokenClaims: {
          email: "morten@godtbrod.no",
          name: "Morten M",
          jobTitle: "Baker",
          officeLocation: "12 Grünerløkka",
          oid: "oid-1",
        },
        accessToken: "at",
      };
    },
  };
  return m;
}

function buildProdApp(onLogin = vi.fn(async () => "/dashboard")) {
  const app = express();
  app.set("trust proxy", 1);
  const msal = makeMsal();
  mountEntraAuth(app, {
    tenantId: "tid",
    clientId: "cid",
    clientSecret: "csec",
    redirectUri: "https://deigverkstedet.apps.gb.logiskbrist.no/api/auth/microsoft/callback",
    handoffSecret: secret,
    onLogin,
    msalClient: msal,
  });
  return { app, msal, onLogin };
}

function buildPreviewApp(onLogin = vi.fn(async () => "/dashboard")) {
  const app = express();
  app.set("trust proxy", 1);
  const msal = makeMsal();
  mountEntraAuth(app, {
    tenantId: "tid",
    clientId: "cid",
    clientSecret: "csec",
    redirectUri: "https://deigverkstedet.apps.gb.logiskbrist.no/api/auth/microsoft/callback",
    prodAuthOrigin: "https://deigverkstedet.apps.gb.logiskbrist.no",
    handoffSecret: secret,
    onLogin,
    msalClient: msal,
  });
  return { app, msal, onLogin };
}

describe("mountEntraAuth — /login on prod", () => {
  it("redirects to Entra with an encrypted state", async () => {
    const { app } = buildProdApp();
    const res = await request(app)
      .get("/api/auth/microsoft/login")
      .set("Host", "deigverkstedet.apps.gb.logiskbrist.no")
      .set("X-Forwarded-Proto", "https");
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.location);
    expect(loc.host).toBe("login.microsoftonline.com");
    const state = loc.searchParams.get("state");
    expect(state).toBeTruthy();
    expect(loc.searchParams.get("redirect_uri")).toBe(
      "https://deigverkstedet.apps.gb.logiskbrist.no/api/auth/microsoft/callback",
    );
  });

  it("returns 400 when target origin doesn't match pattern", async () => {
    const { app } = buildProdApp();
    const res = await request(app)
      .get("/api/auth/microsoft/login")
      .query({ target: "https://evil.example.com" })
      .set("Host", "deigverkstedet.apps.gb.logiskbrist.no")
      .set("X-Forwarded-Proto", "https");
    expect(res.status).toBe(400);
  });

  it("accepts a target that matches the preview pattern", async () => {
    const { app } = buildProdApp();
    const res = await request(app)
      .get("/api/auth/microsoft/login")
      .query({
        target: "https://pr-42-deigverkstedet.apps.gb.logiskbrist.no",
        returnTo: "/dashboard",
      })
      .set("Host", "deigverkstedet.apps.gb.logiskbrist.no")
      .set("X-Forwarded-Proto", "https");
    expect(res.status).toBe(302);
    expect(res.headers.location).toContain("login.microsoftonline.com");
  });
});

describe("mountEntraAuth — /login on preview", () => {
  it("bounces to prod's /login with target and returnTo", async () => {
    const { app } = buildPreviewApp();
    const res = await request(app)
      .get("/api/auth/microsoft/login")
      .query({ returnTo: "/x" })
      .set("Host", "pr-42-deigverkstedet.apps.gb.logiskbrist.no")
      .set("X-Forwarded-Proto", "https");
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.location);
    expect(loc.host).toBe("deigverkstedet.apps.gb.logiskbrist.no");
    expect(loc.pathname).toBe("/api/auth/microsoft/login");
    expect(loc.searchParams.get("target")).toBe(
      "https://pr-42-deigverkstedet.apps.gb.logiskbrist.no",
    );
    expect(loc.searchParams.get("returnTo")).toBe("/x");
  });

  it("neutralizes external returnTo before bouncing", async () => {
    const { app } = buildPreviewApp();
    const res = await request(app)
      .get("/api/auth/microsoft/login")
      .query({ returnTo: "https://evil.com/steal" })
      .set("Host", "pr-42-deigverkstedet.apps.gb.logiskbrist.no")
      .set("X-Forwarded-Proto", "https");
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.location);
    expect(loc.searchParams.get("returnTo")).toBe("/");
  });
});

describe("mountEntraAuth — /callback on prod host", () => {
  it("logs in directly when target matches prod", async () => {
    const onLogin = vi.fn(async (_p: EntraProfile) => "/welcome");
    const { app, msal } = buildProdApp(onLogin);
    // Simulate a state produced by /login: same secret, targetHost = prod
    const state = encryptState(
      {
        csrf: "c",
        codeVerifier: "verifier-xyz",
        targetHost: "deigverkstedet.apps.gb.logiskbrist.no",
        returnTo: "/dashboard",
      },
      secret,
    );
    const res = await request(app)
      .get("/api/auth/microsoft/callback")
      .query({ code: "auth-code-123", state })
      .set("Host", "deigverkstedet.apps.gb.logiskbrist.no")
      .set("X-Forwarded-Proto", "https");
    expect(res.status).toBe(302);
    expect(res.headers.location).toBe("/welcome");
    expect(onLogin).toHaveBeenCalledOnce();
    expect(onLogin.mock.calls[0]![0]!.email).toBe("morten@godtbrod.no");
    expect(msal.lastAcquire?.code).toBe("auth-code-123");
    expect(msal.lastAcquire?.codeVerifier).toBe("verifier-xyz");
  });

  it("issues a handoff redirect when target is a preview host", async () => {
    const { app } = buildProdApp();
    const state = encryptState(
      {
        csrf: "c",
        codeVerifier: "v",
        targetHost: "pr-42-deigverkstedet.apps.gb.logiskbrist.no",
        returnTo: "/afterwards",
      },
      secret,
    );
    const res = await request(app)
      .get("/api/auth/microsoft/callback")
      .query({ code: "auth-code", state })
      .set("Host", "deigverkstedet.apps.gb.logiskbrist.no")
      .set("X-Forwarded-Proto", "https");
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.location);
    expect(loc.host).toBe("pr-42-deigverkstedet.apps.gb.logiskbrist.no");
    expect(loc.pathname).toBe("/api/auth/microsoft/handoff");
    expect(loc.searchParams.get("t")).toBeTruthy();
  });

  it("refuses when tampered state fails to decrypt", async () => {
    const { app } = buildProdApp();
    const res = await request(app)
      .get("/api/auth/microsoft/callback")
      .query({ code: "auth-code", state: "not-a-valid-state" })
      .set("Host", "deigverkstedet.apps.gb.logiskbrist.no")
      .set("X-Forwarded-Proto", "https");
    expect(res.status).toBe(400);
  });

  it("surfaces Entra error params", async () => {
    const { app } = buildProdApp();
    const res = await request(app)
      .get("/api/auth/microsoft/callback")
      .query({
        error: "AADSTS50011",
        error_description: "redirect uri mismatch",
      })
      .set("Host", "deigverkstedet.apps.gb.logiskbrist.no")
      .set("X-Forwarded-Proto", "https");
    expect(res.status).toBe(400);
    expect(res.text).toContain("AADSTS50011");
  });
});

describe("mountEntraAuth — /handoff on preview", () => {
  it("verifies token, calls onLogin, redirects", async () => {
    const onLogin = vi.fn(async (_p: EntraProfile) => "/inbox");
    const { app: preview } = buildPreviewApp(onLogin);

    // Produce a handoff via a prod callback → capture location, replay to preview.
    const { app: prod } = buildProdApp();
    const state = encryptState(
      {
        csrf: "c",
        codeVerifier: "v",
        targetHost: "pr-42-deigverkstedet.apps.gb.logiskbrist.no",
        returnTo: "/inbox",
      },
      secret,
    );
    const cb = await request(prod)
      .get("/api/auth/microsoft/callback")
      .query({ code: "code", state })
      .set("Host", "deigverkstedet.apps.gb.logiskbrist.no")
      .set("X-Forwarded-Proto", "https");
    const loc = new URL(cb.headers.location);
    const token = loc.searchParams.get("t");

    const res = await request(preview)
      .get("/api/auth/microsoft/handoff")
      .query({ t: token })
      .set("Host", "pr-42-deigverkstedet.apps.gb.logiskbrist.no")
      .set("X-Forwarded-Proto", "https");
    expect(res.status).toBe(302);
    expect(res.headers.location).toBe("/inbox");
    expect(onLogin).toHaveBeenCalledOnce();
    expect(onLogin.mock.calls[0]![0]!.email).toBe("morten@godtbrod.no");
  });

  it("rejects a handoff replayed to the wrong preview host", async () => {
    const { app: preview } = buildPreviewApp();
    const { app: prod } = buildProdApp();
    const state = encryptState(
      {
        csrf: "c",
        codeVerifier: "v",
        targetHost: "pr-42-deigverkstedet.apps.gb.logiskbrist.no",
        returnTo: "/",
      },
      secret,
    );
    const cb = await request(prod)
      .get("/api/auth/microsoft/callback")
      .query({ code: "code", state })
      .set("Host", "deigverkstedet.apps.gb.logiskbrist.no")
      .set("X-Forwarded-Proto", "https");
    const loc = new URL(cb.headers.location);
    const token = loc.searchParams.get("t");

    const res = await request(preview)
      .get("/api/auth/microsoft/handoff")
      .query({ t: token })
      .set("Host", "pr-99-deigverkstedet.apps.gb.logiskbrist.no") // wrong preview
      .set("X-Forwarded-Proto", "https");
    expect(res.status).toBe(400);
    expect(res.text).toMatch(/host_mismatch/);
  });

  it("rejects a handoff replay", async () => {
    const onLogin = vi.fn(async () => "/x");
    const { app: preview } = buildPreviewApp(onLogin);
    const { app: prod } = buildProdApp();
    const state = encryptState(
      {
        csrf: "c",
        codeVerifier: "v",
        targetHost: "pr-42-deigverkstedet.apps.gb.logiskbrist.no",
        returnTo: "/",
      },
      secret,
    );
    const cb = await request(prod)
      .get("/api/auth/microsoft/callback")
      .query({ code: "code", state })
      .set("Host", "deigverkstedet.apps.gb.logiskbrist.no")
      .set("X-Forwarded-Proto", "https");
    const token = new URL(cb.headers.location).searchParams.get("t");

    const first = await request(preview)
      .get("/api/auth/microsoft/handoff")
      .query({ t: token })
      .set("Host", "pr-42-deigverkstedet.apps.gb.logiskbrist.no")
      .set("X-Forwarded-Proto", "https");
    expect(first.status).toBe(302);

    const second = await request(preview)
      .get("/api/auth/microsoft/handoff")
      .query({ t: token })
      .set("Host", "pr-42-deigverkstedet.apps.gb.logiskbrist.no")
      .set("X-Forwarded-Proto", "https");
    expect(second.status).toBe(400);
    expect(second.text).toMatch(/replay/);
  });
});
