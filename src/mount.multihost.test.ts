import express from "express";
import { describe, expect, it } from "vitest";
import request from "supertest";
import { mountEntraAuth } from "./mount.js";
import type { MsalLike } from "./types.js";

const secret = "multihost-secret-000000000000000000000000000000";

function makeMsal(): MsalLike {
  return {
    async getAuthCodeUrl(input) {
      return `https://login.microsoftonline.com/tid/authorize?state=${encodeURIComponent(input.state)}`;
    },
    async acquireTokenByCode() {
      return {
        idTokenClaims: { email: "u@godtbrod.no", name: "u" },
        accessToken: "at",
      };
    },
  };
}

function buildApp(opts?: {
  prodAuthOrigin?: string;
  previewOriginPattern?: RegExp;
}) {
  const app = express();
  app.set("trust proxy", 1);
  mountEntraAuth(app, {
    tenantId: "t",
    clientId: "c",
    clientSecret: "s",
    redirectUri: "https://foo.apps.gb.logiskbrist.no/api/auth/microsoft/callback",
    prodAuthOrigin: opts?.prodAuthOrigin,
    previewOriginPattern:
      opts?.previewOriginPattern ??
      /^https:\/\/[a-z0-9-]+\.apps\.(gb\.logiskbrist\.no|godtbrod\.no)$/i,
    handoffSecret: secret,
    onLogin: async () => undefined,
    msalClient: makeMsal(),
  });
  return app;
}

describe("mountEntraAuth — auto-bounce for non-prod hosts", () => {
  it("bounces from a customer-alias host (godtbrod.no) even without prodAuthOrigin set", async () => {
    // Prod pod serves two hosts. gb.logiskbrist.no is the registered URI.
    // A request on godtbrod.no must bounce so the callback + cookie end up
    // on godtbrod.no, not on the registered host.
    const app = buildApp();
    const res = await request(app)
      .get("/api/auth/microsoft/login")
      .query({ returnTo: "/dashboard" })
      .set("Host", "foo.apps.godtbrod.no")
      .set("X-Forwarded-Proto", "https");
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.location);
    expect(loc.host).toBe("foo.apps.gb.logiskbrist.no"); // bounce origin from prodHost
    expect(loc.pathname).toBe("/api/auth/microsoft/login");
    expect(loc.searchParams.get("target")).toBe("https://foo.apps.godtbrod.no");
    expect(loc.searchParams.get("returnTo")).toBe("/dashboard");
  });

  it("does NOT bounce when already on the prod host", async () => {
    const app = buildApp();
    const res = await request(app)
      .get("/api/auth/microsoft/login")
      .set("Host", "foo.apps.gb.logiskbrist.no")
      .set("X-Forwarded-Proto", "https");
    expect(res.status).toBe(302);
    // Direct to Entra, not another bounce.
    const loc = new URL(res.headers.location);
    expect(loc.host).toBe("login.microsoftonline.com");
  });

  it("bounces preview hosts to prodAuthOrigin when set (unchanged behaviour)", async () => {
    const app = buildApp({
      prodAuthOrigin: "https://foo.apps.gb.logiskbrist.no",
    });
    const res = await request(app)
      .get("/api/auth/microsoft/login")
      .set("Host", "pr-5-foo.apps.gb.logiskbrist.no")
      .set("X-Forwarded-Proto", "https");
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.location);
    expect(loc.host).toBe("foo.apps.gb.logiskbrist.no");
    expect(loc.searchParams.get("target")).toBe(
      "https://pr-5-foo.apps.gb.logiskbrist.no",
    );
  });
});
