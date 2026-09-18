// Next.js App Router adapter for the preview-aware Entra broker.
//
// Same core logic as `mountEntraAuth` (Express) — only the request/response
// glue differs. Consumers wire three route handlers:
//
//   // app/api/auth/microsoft/route.ts
//   import { NextRequest } from "next/server";
//   import { handleLogin } from "@logiskbrist/logisk-platform-auth/next";
//   export async function GET(req: NextRequest) {
//     return handleLogin(req, options);
//   }
//
//   // app/api/auth/microsoft/callback/route.ts        → handleCallback
//   // app/api/auth/microsoft/handoff/route.ts          → handleHandoff
//
// `onLogin` in this API takes NextRequest (not Express Request) and may set
// cookies via `next/headers`' `cookies()` before returning a redirect URL
// — those cookies are included in the redirect response.

import { createHash, randomBytes } from "node:crypto";
import type { NextRequest } from "next/server";
import { NextResponse } from "next/server";
import { HandoffError, signHandoff, verifyHandoff } from "./handoff.js";
import { MemoryNonceCache } from "./nonce.js";
import { decryptState, encryptState, StateError } from "./state.js";
import type {
  AuthErrorInfo,
  EntraProfile,
  MsalLike,
  NonceCache,
  RouteConfig,
} from "./types.js";
import {
  defaultPreviewOriginPattern,
  isAllowedPreviewOrigin,
  safeReturnTo,
} from "./validate.js";

const DEFAULT_SCOPES = ["openid", "profile", "email", "User.Read"];
const DEFAULT_ROUTES: RouteConfig = {
  login: "/api/auth/microsoft/login",
  callback: "/api/auth/microsoft/callback",
  handoff: "/api/auth/microsoft/handoff",
};

export type NextOnLogin = (
  profile: EntraProfile,
  req: NextRequest,
  returnTo: string,
) =>
  | Promise<string | undefined | void>
  | string
  | undefined
  | void;

export type NextOnError = (
  info: AuthErrorInfo,
  req: NextRequest,
) =>
  | Promise<string | undefined | void>
  | string
  | undefined
  | void;

export type NextEnrichProfile = (
  profile: EntraProfile,
  accessToken: string | null,
) => Promise<EntraProfile> | EntraProfile;

export interface NextMountOptions {
  tenantId: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  prodAuthOrigin?: string;
  handoffSecret: string;
  routes?: Partial<RouteConfig>;
  scopes?: string[];
  onLogin: NextOnLogin;
  onError?: NextOnError;
  enrichProfile?: NextEnrichProfile;
  authorizeExtras?: Record<string, string>;
  previewOriginPattern?: RegExp;
  handoffTtlSeconds?: number;
  stateTtlSeconds?: number;
  msalClient?: MsalLike;
  nonceCache?: NonceCache;
  now?: () => number;
}

interface ResolvedConfig {
  routes: RouteConfig;
  scopes: string[];
  handoffTtl: number;
  stateTtl: number;
  now: () => number;
  nonceCache: NonceCache;
  previewPattern: RegExp;
  prodHost: string;
  msalPromise: Promise<MsalLike>;
}

// Shared per-options config, memoized by options identity so
// multiple route handlers all share the nonce cache + MSAL client.
const configCache = new WeakMap<NextMountOptions, ResolvedConfig>();

function resolve(options: NextMountOptions): ResolvedConfig {
  const cached = configCache.get(options);
  if (cached) return cached;
  const routes: RouteConfig = { ...DEFAULT_ROUTES, ...options.routes };
  const scopes = options.scopes ?? DEFAULT_SCOPES;
  const handoffTtl = options.handoffTtlSeconds ?? 60;
  const stateTtl = options.stateTtlSeconds ?? 600;
  const now = options.now ?? (() => Date.now());
  const nonceCache: NonceCache = options.nonceCache ?? new MemoryNonceCache(now);
  const previewPattern =
    options.previewOriginPattern ?? defaultPreviewOriginPattern(options.redirectUri);
  const prodHost = new URL(options.redirectUri).host;
  const msalPromise: Promise<MsalLike> = options.msalClient
    ? Promise.resolve(options.msalClient)
    : createDefaultMsal(options);
  const cfg: ResolvedConfig = {
    routes,
    scopes,
    handoffTtl,
    stateTtl,
    now,
    nonceCache,
    previewPattern,
    prodHost,
    msalPromise,
  };
  configCache.set(options, cfg);
  return cfg;
}

async function createDefaultMsal(options: NextMountOptions): Promise<MsalLike> {
  const msalNode = await import("@azure/msal-node");
  const client = new msalNode.ConfidentialClientApplication({
    auth: {
      clientId: options.clientId,
      authority: `https://login.microsoftonline.com/${options.tenantId}`,
      clientSecret: options.clientSecret,
    },
  });
  return {
    async getAuthCodeUrl(input) {
      return client.getAuthCodeUrl(input);
    },
    async acquireTokenByCode(input) {
      const res = await client.acquireTokenByCode(input);
      if (!res) throw new Error("MSAL returned no token response");
      return {
        idTokenClaims:
          (res.idTokenClaims as Record<string, unknown> | undefined) ?? {},
        accessToken: res.accessToken ?? null,
      };
    },
  };
}

function reqHost(req: NextRequest): string {
  // Behind a proxy (ingress-nginx / cloud load balancers) prefer
  // x-forwarded-host over the tunneled internal host header.
  return (
    req.headers.get("x-forwarded-host") ??
    req.headers.get("host") ??
    new URL(req.url).host
  );
}

function reqProtocol(req: NextRequest): string {
  const xfp = req.headers.get("x-forwarded-proto");
  if (xfp) return xfp.split(",")[0]!.trim();
  try {
    return new URL(req.url).protocol.replace(":", "");
  } catch {
    return "https";
  }
}

async function fail(
  options: NextMountOptions,
  req: NextRequest,
  info: AuthErrorInfo,
  defaultStatus: number,
  defaultBody: string,
): Promise<NextResponse> {
  if (options.onError) {
    let redirect: string | undefined | void;
    try {
      redirect = await options.onError(info, req);
    } catch {
      // onError itself threw — fall through to default response.
    }
    if (redirect) {
      return NextResponse.redirect(new URL(safeReturnTo(redirect), req.url), 302);
    }
  }
  return new NextResponse(defaultBody, { status: defaultStatus });
}

export async function handleLogin(
  req: NextRequest,
  options: NextMountOptions,
): Promise<NextResponse> {
  const cfg = resolve(options);
  const returnTo = safeReturnTo(req.nextUrl.searchParams.get("returnTo") ?? undefined);
  const host = reqHost(req);
  const bounceOrigin = options.prodAuthOrigin ?? `https://${cfg.prodHost}`;
  if (host !== cfg.prodHost) {
    const target = `${reqProtocol(req)}://${host}`;
    const url = new URL(cfg.routes.login, bounceOrigin);
    url.searchParams.set("target", target);
    url.searchParams.set("returnTo", returnTo);
    return NextResponse.redirect(url.toString(), 302);
  }
  let targetHost = cfg.prodHost;
  const target = req.nextUrl.searchParams.get("target");
  if (target) {
    if (!isAllowedPreviewOrigin(target, cfg.previewPattern)) {
      return fail(
        options,
        req,
        { code: "target_origin_denied", step: "login" },
        400,
        "target origin not allowed",
      );
    }
    targetHost = new URL(target).host;
  }
  const csrf = randomBytes(16).toString("base64url");
  const codeVerifier = randomBytes(32).toString("base64url");
  const codeChallenge = createHash("sha256").update(codeVerifier).digest("base64url");
  const state = encryptState(
    { csrf, codeVerifier, targetHost, returnTo },
    options.handoffSecret,
    { now: cfg.now },
  );
  let authUrl: string;
  try {
    const msal = await cfg.msalPromise;
    authUrl = await msal.getAuthCodeUrl({
      scopes: cfg.scopes,
      redirectUri: options.redirectUri,
      state,
      codeChallenge,
      codeChallengeMethod: "S256",
      ...(options.authorizeExtras ?? {}),
    });
  } catch (err) {
    return fail(
      options,
      req,
      { code: "start_failed", step: "login", error: err },
      500,
      "failed to start login",
    );
  }
  return NextResponse.redirect(authUrl, 302);
}

export async function handleCallback(
  req: NextRequest,
  options: NextMountOptions,
): Promise<NextResponse> {
  const cfg = resolve(options);
  const host = reqHost(req);
  if (host !== cfg.prodHost) {
    return fail(
      options,
      req,
      { code: "callback_wrong_host", step: "callback" },
      400,
      "callback must run on prod host",
    );
  }
  const code = req.nextUrl.searchParams.get("code");
  const stateStr = req.nextUrl.searchParams.get("state");
  if (!code || !stateStr) {
    const entraError = req.nextUrl.searchParams.get("error");
    const entraDescription = req.nextUrl.searchParams.get("error_description");
    return fail(
      options,
      req,
      entraError
        ? {
            code: "entra_denied",
            step: "callback",
            entraError,
            entraDescription: entraDescription ?? undefined,
          }
        : { code: "missing_code_or_state", step: "callback" },
      400,
      entraError ? `${entraError}: ${entraDescription ?? ""}` : "missing code or state",
    );
  }
  let payload;
  try {
    payload = decryptState(stateStr, options.handoffSecret, {
      ttlSeconds: cfg.stateTtl,
      now: cfg.now,
    });
  } catch (err) {
    if (err instanceof StateError) {
      return fail(
        options,
        req,
        { code: `state_${err.code}`, step: "callback", error: err },
        400,
        `state ${err.code}`,
      );
    }
    return fail(
      options,
      req,
      { code: "state_decrypt_failed", step: "callback", error: err },
      500,
      "state decrypt failed",
    );
  }
  let tokens;
  try {
    const msal = await cfg.msalPromise;
    tokens = await msal.acquireTokenByCode({
      code,
      scopes: cfg.scopes,
      redirectUri: options.redirectUri,
      codeVerifier: payload.codeVerifier,
    });
  } catch (err) {
    return fail(
      options,
      req,
      { code: "token_exchange", step: "callback", error: err },
      400,
      "token exchange failed",
    );
  }
  let profile = extractProfile(tokens.idTokenClaims);
  if (!profile) {
    return fail(
      options,
      req,
      { code: "no_email", step: "callback" },
      400,
      "no email in id token",
    );
  }
  if (options.enrichProfile) {
    try {
      profile = await options.enrichProfile(profile, tokens.accessToken);
    } catch (err) {
      return fail(
        options,
        req,
        { code: "enrich_failed", step: "callback", error: err },
        500,
        "profile enrichment failed",
      );
    }
  }
  const returnTo = safeReturnTo(payload.returnTo);
  if (payload.targetHost === cfg.prodHost) {
    try {
      const override = await options.onLogin(profile, req, returnTo);
      const dest = override ? safeReturnTo(override) : returnTo;
      return NextResponse.redirect(new URL(dest, req.url), 302);
    } catch (err) {
      return fail(
        options,
        req,
        { code: "session_setup", step: "callback", error: err },
        500,
        "session setup failed",
      );
    }
  }
  const token = signHandoff(
    {
      profile,
      targetHost: payload.targetHost,
      returnTo,
      ttlSeconds: cfg.handoffTtl,
      now: cfg.now,
    },
    options.handoffSecret,
  );
  const handoffUrl = new URL(cfg.routes.handoff, `https://${payload.targetHost}`);
  handoffUrl.searchParams.set("t", token);
  return NextResponse.redirect(handoffUrl.toString(), 302);
}

export async function handleHandoff(
  req: NextRequest,
  options: NextMountOptions,
): Promise<NextResponse> {
  const cfg = resolve(options);
  const token = req.nextUrl.searchParams.get("t");
  if (!token) {
    return fail(
      options,
      req,
      { code: "missing_token", step: "handoff" },
      400,
      "missing handoff token",
    );
  }
  const expectedTargetHost = reqHost(req);
  try {
    const payload = verifyHandoff(
      {
        token,
        expectedTargetHost,
        now: cfg.now,
        markNonceUsed: (n, ttl) => cfg.nonceCache.markUsed(n, ttl),
      },
      options.handoffSecret,
    );
    const returnTo = safeReturnTo(payload.returnTo);
    const override = await options.onLogin(payload.profile, req, returnTo);
    const dest = override ? safeReturnTo(override) : returnTo;
    return NextResponse.redirect(new URL(dest, req.url), 302);
  } catch (err) {
    if (err instanceof HandoffError) {
      return fail(
        options,
        req,
        { code: `handoff_${err.code}`, step: "handoff", error: err },
        400,
        `handoff ${err.code}`,
      );
    }
    return fail(
      options,
      req,
      { code: "handoff_failed", step: "handoff", error: err },
      500,
      "handoff failed",
    );
  }
}

function extractProfile(
  claims: Record<string, unknown>,
): EntraProfile | null {
  const email =
    pickString(claims, "email") ??
    pickString(claims, "preferred_username") ??
    pickString(claims, "upn");
  if (!email) return null;
  return {
    email,
    displayName:
      pickString(claims, "name") ?? pickString(claims, "given_name") ?? null,
    jobTitle: pickString(claims, "jobTitle") ?? null,
    officeLocation: pickString(claims, "officeLocation") ?? null,
    raw: claims,
  };
}

function pickString(o: Record<string, unknown>, k: string): string | undefined {
  const v = o[k];
  return typeof v === "string" && v.length > 0 ? v : undefined;
}
