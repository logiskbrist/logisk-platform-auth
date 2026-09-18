import express from "express";
import { describe, expect, it } from "vitest";
import request from "supertest";
import { mountEntraAuth } from "./mount.js";
import { encryptState } from "./state.js";
import type { EntraProfile, MsalLike } from "./types.js";

const secret = "returnto-secret-00000000000000000000000000000000";

function makeMsal(): MsalLike {
  return {
    async getAuthCodeUrl(input) {
      return `https://login.microsoftonline.com/tid/authorize?state=${encodeURIComponent(input.state)}`;
    },
    async acquireTokenByCode() {
      return {
        idTokenClaims: { email: "user@godtbrod.no", name: "U" },
        accessToken: "at",
      };
    },
  };
}

function buildProdApp(onLogin: (p: EntraProfile, req: express.Request, rt: string) => string | undefined | void | Promise<string | undefined | void>) {
  const app = express();
  app.set("trust proxy", 1);
  mountEntraAuth(app, {
    tenantId: "t",
    clientId: "c",
    clientSecret: "s",
    redirectUri: "https://foo.apps.gb.logiskbrist.no/api/auth/microsoft/callback",
    handoffSecret: secret,
    onLogin,
    msalClient: makeMsal(),
  });
  return app;
}

describe("mountEntraAuth — returnTo semantics", () => {
  it("falls back to state's returnTo when onLogin returns empty string", async () => {
    const app = buildProdApp((_p, _req, _rt) => "");
    const state = encryptState(
      {
        csrf: "c",
        codeVerifier: "v",
        targetHost: "foo.apps.gb.logiskbrist.no",
        returnTo: "/deep/link",
      },
      secret,
    );
    const res = await request(app)
      .get("/api/auth/microsoft/callback")
      .query({ code: "x", state })
      .set("Host", "foo.apps.gb.logiskbrist.no")
      .set("X-Forwarded-Proto", "https");
    expect(res.status).toBe(302);
    expect(res.headers.location).toBe("/deep/link");
  });

  it("falls back to state's returnTo when onLogin returns undefined", async () => {
    const app = buildProdApp(() => undefined);
    const state = encryptState(
      {
        csrf: "c",
        codeVerifier: "v",
        targetHost: "foo.apps.gb.logiskbrist.no",
        returnTo: "/inbox",
      },
      secret,
    );
    const res = await request(app)
      .get("/api/auth/microsoft/callback")
      .query({ code: "x", state })
      .set("Host", "foo.apps.gb.logiskbrist.no")
      .set("X-Forwarded-Proto", "https");
    expect(res.status).toBe(302);
    expect(res.headers.location).toBe("/inbox");
  });

  it("uses onLogin's return value when non-empty (overrides state's returnTo)", async () => {
    const app = buildProdApp(() => "/override");
    const state = encryptState(
      {
        csrf: "c",
        codeVerifier: "v",
        targetHost: "foo.apps.gb.logiskbrist.no",
        returnTo: "/state-value",
      },
      secret,
    );
    const res = await request(app)
      .get("/api/auth/microsoft/callback")
      .query({ code: "x", state })
      .set("Host", "foo.apps.gb.logiskbrist.no")
      .set("X-Forwarded-Proto", "https");
    expect(res.status).toBe(302);
    expect(res.headers.location).toBe("/override");
  });

  it("passes returnTo to onLogin as third arg", async () => {
    let seen = "";
    const app = buildProdApp((_p, _req, rt) => {
      seen = rt;
      return undefined;
    });
    const state = encryptState(
      {
        csrf: "c",
        codeVerifier: "v",
        targetHost: "foo.apps.gb.logiskbrist.no",
        returnTo: "/original",
      },
      secret,
    );
    await request(app)
      .get("/api/auth/microsoft/callback")
      .query({ code: "x", state })
      .set("Host", "foo.apps.gb.logiskbrist.no")
      .set("X-Forwarded-Proto", "https");
    expect(seen).toBe("/original");
  });
});
