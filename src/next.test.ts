import { describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";
import {
  handleCallback,
  handleHandoff,
  handleLogin,
  type NextMountOptions,
} from "./next.js";
import { encryptState } from "./state.js";
import type { EntraProfile, MsalLike } from "./types.js";

const secret = "next-adapter-secret-00000000000000000000000000000000";
const PROD_HOST = "foo.apps.gb.logiskbrist.no";
const REDIRECT_URI = `https://${PROD_HOST}/api/auth/microsoft/callback`;

function makeMsal(): MsalLike {
  return {
    async getAuthCodeUrl(input) {
      return `https://login.microsoftonline.com/tid/authorize?state=${encodeURIComponent(
        input.state,
      )}&redirect_uri=${encodeURIComponent(input.redirectUri)}`;
    },
    async acquireTokenByCode() {
      return {
        idTokenClaims: {
          email: "morten@godtbrod.no",
          name: "Morten M",
          oid: "oid-1",
        },
        accessToken: "at",
      };
    },
  };
}

function baseOptions(
  overrides: Partial<NextMountOptions> = {},
): NextMountOptions {
  return {
    tenantId: "tid",
    clientId: "cid",
    clientSecret: "csec",
    redirectUri: REDIRECT_URI,
    handoffSecret: secret,
    onLogin: vi.fn(async () => "/dashboard"),
    msalClient: makeMsal(),
    ...overrides,
  };
}

function reqOn(
  host: string,
  path: string,
  query: Record<string, string> = {},
): NextRequest {
  const url = new URL(`https://${host}${path}`);
  for (const [k, v] of Object.entries(query)) url.searchParams.set(k, v);
  return new NextRequest(url, {
    headers: {
      host,
      "x-forwarded-proto": "https",
      "x-forwarded-host": host,
    },
  });
}

// NextResponse.redirect normalizes to 307. Tests just check "it's a redirect".
function expectRedirect(res: Response): void {
  expect(res.status).toBeGreaterThanOrEqual(300);
  expect(res.status).toBeLessThan(400);
}

describe("next adapter — handleLogin", () => {
  it("redirects to Entra with an encrypted state on the prod host", async () => {
    const res = await handleLogin(
      reqOn(PROD_HOST, "/api/auth/microsoft/login"),
      baseOptions(),
    );
    expectRedirect(res);
    const loc = new URL(res.headers.get("location")!);
    expect(loc.host).toBe("login.microsoftonline.com");
    expect(loc.searchParams.get("state")).toBeTruthy();
    expect(loc.searchParams.get("redirect_uri")).toBe(REDIRECT_URI);
  });

  it("bounces from preview host to prod host with target + returnTo", async () => {
    const res = await handleLogin(
      reqOn("pr-42-foo.apps.gb.logiskbrist.no", "/api/auth/microsoft/login", {
        returnTo: "/inbox",
      }),
      baseOptions(),
    );
    expectRedirect(res);
    const loc = new URL(res.headers.get("location")!);
    expect(loc.host).toBe(PROD_HOST);
    expect(loc.pathname).toBe("/api/auth/microsoft/login");
    expect(loc.searchParams.get("target")).toBe(
      "https://pr-42-foo.apps.gb.logiskbrist.no",
    );
    expect(loc.searchParams.get("returnTo")).toBe("/inbox");
  });

  it("also bounces the customer-alias host", async () => {
    const res = await handleLogin(
      reqOn("foo.apps.godtbrod.no", "/api/auth/microsoft/login"),
      baseOptions({
        previewOriginPattern:
          /^https:\/\/[a-z0-9-]+\.apps\.(gb\.logiskbrist\.no|godtbrod\.no)$/i,
      }),
    );
    expectRedirect(res);
    const loc = new URL(res.headers.get("location")!);
    expect(loc.host).toBe(PROD_HOST);
    expect(loc.searchParams.get("target")).toBe(
      "https://foo.apps.godtbrod.no",
    );
  });

  it("rejects a target that doesn't match the preview pattern", async () => {
    const res = await handleLogin(
      reqOn(PROD_HOST, "/api/auth/microsoft/login", {
        target: "https://evil.example.com",
      }),
      baseOptions(),
    );
    expect(res.status).toBe(400);
  });
});

describe("next adapter — handleCallback", () => {
  it("direct-prod: exchanges the code and redirects via onLogin", async () => {
    const onLogin = vi.fn(async () => "/welcome");
    const options = baseOptions({ onLogin });
    const state = encryptState(
      {
        csrf: "c",
        codeVerifier: "v",
        targetHost: PROD_HOST,
        returnTo: "/",
      },
      secret,
    );
    const res = await handleCallback(
      reqOn(PROD_HOST, "/api/auth/microsoft/callback", {
        code: "auth-code",
        state,
      }),
      options,
    );
    expectRedirect(res);
    const loc = res.headers.get("location")!;
    expect(loc.endsWith("/welcome")).toBe(true);
    expect(onLogin).toHaveBeenCalledOnce();
    const gotProfile = onLogin.mock.calls[0]![0]! as EntraProfile;
    expect(gotProfile.email).toBe("morten@godtbrod.no");
  });

  it("preview target: issues a handoff redirect back to the preview host", async () => {
    const options = baseOptions();
    const state = encryptState(
      {
        csrf: "c",
        codeVerifier: "v",
        targetHost: "pr-42-foo.apps.gb.logiskbrist.no",
        returnTo: "/inbox",
      },
      secret,
    );
    const res = await handleCallback(
      reqOn(PROD_HOST, "/api/auth/microsoft/callback", {
        code: "auth-code",
        state,
      }),
      options,
    );
    expectRedirect(res);
    const loc = new URL(res.headers.get("location")!);
    expect(loc.host).toBe("pr-42-foo.apps.gb.logiskbrist.no");
    expect(loc.pathname).toBe("/api/auth/microsoft/handoff");
    expect(loc.searchParams.get("t")).toBeTruthy();
  });

  it("refuses when the callback lands on a non-prod host", async () => {
    const res = await handleCallback(
      reqOn("pr-42-foo.apps.gb.logiskbrist.no", "/api/auth/microsoft/callback", {
        code: "x",
        state: "y",
      }),
      baseOptions(),
    );
    expect(res.status).toBe(400);
  });

  it("routes onError → redirect on Entra denial", async () => {
    const options = baseOptions({
      onError: (info) => {
        if (info.code === "entra_denied") return "/auth/login?feil=konto";
        return undefined;
      },
    });
    const res = await handleCallback(
      reqOn(PROD_HOST, "/api/auth/microsoft/callback", {
        error: "access_denied",
        error_description: "user cancelled",
      }),
      options,
    );
    expectRedirect(res);
    expect(res.headers.get("location")!.endsWith("/auth/login?feil=konto")).toBe(
      true,
    );
  });
});

describe("next adapter — handleHandoff", () => {
  it("full loop: prod callback → preview handoff → onLogin", async () => {
    const onLogin = vi.fn(async () => "/inbox");
    const previewOptions = baseOptions({ onLogin });
    const prodOptions = baseOptions();
    const state = encryptState(
      {
        csrf: "c",
        codeVerifier: "v",
        targetHost: "pr-42-foo.apps.gb.logiskbrist.no",
        returnTo: "/inbox",
      },
      secret,
    );
    const callbackRes = await handleCallback(
      reqOn(PROD_HOST, "/api/auth/microsoft/callback", {
        code: "code",
        state,
      }),
      prodOptions,
    );
    const handoffUrl = new URL(callbackRes.headers.get("location")!);
    const t = handoffUrl.searchParams.get("t")!;
    const previewReq = reqOn(
      "pr-42-foo.apps.gb.logiskbrist.no",
      "/api/auth/microsoft/handoff",
      { t },
    );
    const res = await handleHandoff(previewReq, previewOptions);
    expectRedirect(res);
    expect(res.headers.get("location")!.endsWith("/inbox")).toBe(true);
    expect(onLogin).toHaveBeenCalledOnce();
    const gotProfile = onLogin.mock.calls[0]![0]! as EntraProfile;
    expect(gotProfile.email).toBe("morten@godtbrod.no");
  });

  it("rejects a handoff replayed to the wrong host", async () => {
    const options = baseOptions();
    const state = encryptState(
      {
        csrf: "c",
        codeVerifier: "v",
        targetHost: "pr-42-foo.apps.gb.logiskbrist.no",
        returnTo: "/",
      },
      secret,
    );
    const callbackRes = await handleCallback(
      reqOn(PROD_HOST, "/api/auth/microsoft/callback", { code: "c", state }),
      options,
    );
    const t = new URL(callbackRes.headers.get("location")!).searchParams.get(
      "t",
    )!;
    const res = await handleHandoff(
      reqOn(
        "pr-99-foo.apps.gb.logiskbrist.no",
        "/api/auth/microsoft/handoff",
        { t },
      ),
      options,
    );
    expect(res.status).toBe(400);
  });
});
