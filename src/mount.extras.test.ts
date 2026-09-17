import express from "express";
import { describe, expect, it, vi } from "vitest";
import request from "supertest";
import { mountEntraAuth } from "./mount.js";
import { encryptState } from "./state.js";
import type { EntraProfile, MsalLike } from "./types.js";

const secret = "extras-test-secret-0000000000000000000000000000";

function makeMsal() {
  const captured: {
    lastAuthCodeUrl?: Parameters<MsalLike["getAuthCodeUrl"]>[0];
  } = {};
  const m: MsalLike = {
    async getAuthCodeUrl(input) {
      captured.lastAuthCodeUrl = input;
      return `https://login.microsoftonline.com/tid/authorize?state=${encodeURIComponent(
        input.state,
      )}`;
    },
    async acquireTokenByCode() {
      return {
        idTokenClaims: {
          email: "user@godtbrod.no",
          name: "User",
        },
        accessToken: "access-token-42",
      };
    },
  };
  return { m, captured };
}

describe("mountEntraAuth — authorizeExtras", () => {
  it("forwards prompt=select_account into the MSAL request", async () => {
    const { m: msal, captured } = makeMsal();
    const app = express();
    app.set("trust proxy", 1);
    mountEntraAuth(app, {
      tenantId: "t",
      clientId: "c",
      clientSecret: "s",
      redirectUri: "https://foo.apps.gb.logiskbrist.no/api/auth/microsoft/callback",
      handoffSecret: secret,
      onLogin: async () => "/",
      msalClient: msal,
      authorizeExtras: { prompt: "select_account" },
    });
    const res = await request(app)
      .get("/api/auth/microsoft/login")
      .set("Host", "foo.apps.gb.logiskbrist.no")
      .set("X-Forwarded-Proto", "https");
    expect(res.status).toBe(302);
    expect(captured.lastAuthCodeUrl?.prompt).toBe("select_account");
  });
});

describe("mountEntraAuth — enrichProfile", () => {
  it("runs on prod after the token exchange and hands off the enriched profile", async () => {
    const enrich = vi.fn(
      async (p: EntraProfile, accessToken: string | null): Promise<EntraProfile> => ({
        ...p,
        jobTitle: "Baker",
        officeLocation: "12 Grünerløkka",
        raw: { ...p.raw, gotAccessToken: accessToken !== null },
      }),
    );
    const onLoginPreview = vi.fn(async () => "/preview-done");
    const { m: msal } = makeMsal();

    // Prod-side app (has enrichProfile)
    const prod = express();
    prod.set("trust proxy", 1);
    mountEntraAuth(prod, {
      tenantId: "t",
      clientId: "c",
      clientSecret: "s",
      redirectUri: "https://foo.apps.gb.logiskbrist.no/api/auth/microsoft/callback",
      handoffSecret: secret,
      onLogin: async () => "/",
      enrichProfile: enrich,
      msalClient: msal,
    });

    // Preview-side app: onLogin sees whatever the handoff carried
    const preview = express();
    preview.set("trust proxy", 1);
    mountEntraAuth(preview, {
      tenantId: "t",
      clientId: "c",
      clientSecret: "s",
      redirectUri: "https://foo.apps.gb.logiskbrist.no/api/auth/microsoft/callback",
      prodAuthOrigin: "https://foo.apps.gb.logiskbrist.no",
      handoffSecret: secret,
      onLogin: onLoginPreview,
      msalClient: msal,
    });

    const state = encryptState(
      {
        csrf: "c",
        codeVerifier: "v",
        targetHost: "pr-5-foo.apps.gb.logiskbrist.no",
        returnTo: "/",
      },
      secret,
    );
    const cb = await request(prod)
      .get("/api/auth/microsoft/callback")
      .query({ code: "code", state })
      .set("Host", "foo.apps.gb.logiskbrist.no")
      .set("X-Forwarded-Proto", "https");
    expect(cb.status).toBe(302);
    expect(enrich).toHaveBeenCalledOnce();
    expect(enrich.mock.calls[0]![1]).toBe("access-token-42");

    const token = new URL(cb.headers.location).searchParams.get("t");
    const res = await request(preview)
      .get("/api/auth/microsoft/handoff")
      .query({ t: token })
      .set("Host", "pr-5-foo.apps.gb.logiskbrist.no")
      .set("X-Forwarded-Proto", "https");
    expect(res.status).toBe(302);
    const gotProfile = onLoginPreview.mock.calls[0]![0]!;
    expect(gotProfile.jobTitle).toBe("Baker");
    expect(gotProfile.officeLocation).toBe("12 Grünerløkka");
    expect(gotProfile.raw.gotAccessToken).toBe(true);
  });

  it("aborts login with 500 if enrichProfile throws", async () => {
    const { m: msal } = makeMsal();
    const app = express();
    app.set("trust proxy", 1);
    mountEntraAuth(app, {
      tenantId: "t",
      clientId: "c",
      clientSecret: "s",
      redirectUri: "https://foo.apps.gb.logiskbrist.no/api/auth/microsoft/callback",
      handoffSecret: secret,
      onLogin: async () => "/",
      enrichProfile: async () => {
        throw new Error("graph down");
      },
      msalClient: msal,
    });
    const state = encryptState(
      {
        csrf: "c",
        codeVerifier: "v",
        targetHost: "foo.apps.gb.logiskbrist.no",
        returnTo: "/",
      },
      secret,
    );
    const res = await request(app)
      .get("/api/auth/microsoft/callback")
      .query({ code: "code", state })
      .set("Host", "foo.apps.gb.logiskbrist.no")
      .set("X-Forwarded-Proto", "https");
    expect(res.status).toBe(500);
  });
});
