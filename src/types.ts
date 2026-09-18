import type { Request } from "express";

/**
 * Minimal profile shape returned from Entra `/me` + id-token claims.
 *
 * Extra fields the app cares about live in `raw` — untyped, whatever Entra sent.
 */
export interface EntraProfile {
  email: string;
  displayName: string | null;
  jobTitle: string | null;
  officeLocation: string | null;
  raw: Record<string, unknown>;
}

/**
 * The `onLogin` hook the host app implements. Called on both direct-prod and
 * preview-handoff paths with a verified Entra profile.
 *
 * Return a URL to redirect the browser to next. Must be a same-origin path
 * (starts with `/`) — the package rejects other shapes. Return an empty
 * string / `undefined` to redirect to the `returnTo` the browser started with.
 */
export type OnLogin = (
  profile: EntraProfile,
  req: Request,
  returnTo: string,
) => Promise<string | undefined | void> | string | undefined | void;

export interface RouteConfig {
  /** Kicks off the flow. Default: /api/auth/microsoft/login */
  login: string;
  /** Entra callback — only reachable on the prod host. Default: /api/auth/microsoft/callback */
  callback: string;
  /** Preview receiver for the handoff JWT. Default: /api/auth/microsoft/handoff */
  handoff: string;
}

export interface MountOptions {
  tenantId: string;
  clientId: string;
  clientSecret: string;
  /**
   * The one redirect URI registered in Entra. Same value in every pod of the
   * same app — prod pods hit it directly, preview pods bounce through it.
   */
  redirectUri: string;
  /**
   * Origin (scheme + host, no path) of the prod pod, as previews should
   * reach it. Preview-only: unset on prod pods.
   */
  prodAuthOrigin?: string;
  /**
   * HS256 signing key for the handoff JWT and AES key material for the
   * OAuth state. Same value in every pod of the same app.
   */
  handoffSecret: string;
  routes?: Partial<RouteConfig>;
  scopes?: string[];
  onLogin: OnLogin;
  /**
   * Runs on the prod pod right after the code-for-token exchange, before the
   * profile is baked into the handoff JWT. Use this to enrich the profile
   * with data the ID token doesn't carry — e.g. `jobTitle` / `officeLocation`
   * via Microsoft Graph `/me` with the access token — since only the prod pod
   * ever holds the access token. Best-effort: throw to abort login, return an
   * unchanged profile to skip.
   */
  enrichProfile?: (
    profile: EntraProfile,
    accessToken: string | null,
  ) => Promise<EntraProfile> | EntraProfile;
  /**
   * Extra query params forwarded to `msal.getAuthCodeUrl`, e.g. `prompt`,
   * `login_hint`, `domain_hint`. `select_account` forces an account picker
   * each login.
   */
  authorizeExtras?: Record<string, string>;
  /**
   * Pattern the preview `target` origin must match before prod will bounce
   * a handoff to it. Default: same registrable host + one subdomain level as
   * `redirectUri`, e.g. from `https://foo.apps.godtbrod.no` allows any
   * `https://<x>.apps.godtbrod.no`.
   */
  previewOriginPattern?: RegExp;
  /**
   * TTL for the handoff JWT in seconds. Default 60.
   */
  handoffTtlSeconds?: number;
  /**
   * TTL for the encrypted OAuth state in seconds. Default 600 (10 min —
   * users may sit on the Entra consent screen).
   */
  stateTtlSeconds?: number;
  /**
   * Override the MSAL client. Used for tests.
   */
  msalClient?: MsalLike;
  /**
   * Override the nonce cache. Used for tests, or to plug in a shared store
   * across replicas (default is per-process memory).
   */
  nonceCache?: NonceCache;
  /** Injected clock, for tests. */
  now?: () => number;
}

export interface NonceCache {
  markUsed(nonce: string, ttlSeconds: number): boolean;
}

export interface MsalLike {
  getAuthCodeUrl(input: {
    scopes: string[];
    redirectUri: string;
    state: string;
    codeChallenge: string;
    codeChallengeMethod: "S256";
    prompt?: string;
    loginHint?: string;
    domainHint?: string;
    [extra: string]: unknown;
  }): Promise<string>;
  acquireTokenByCode(input: {
    code: string;
    scopes: string[];
    redirectUri: string;
    codeVerifier: string;
  }): Promise<{
    idTokenClaims: Record<string, unknown>;
    accessToken: string | null;
  }>;
}

/** Payload we pack into the OAuth state parameter (encrypted). */
export interface StatePayload {
  csrf: string;
  codeVerifier: string;
  targetHost: string;
  returnTo: string;
  iat: number;
}

/** Payload of the preview handoff JWT (signed, not encrypted). */
export interface HandoffPayload {
  profile: EntraProfile;
  targetHost: string;
  returnTo: string;
  nonce: string;
  iat: number;
  exp: number;
}
