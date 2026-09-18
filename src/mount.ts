import { createHash, randomBytes } from "node:crypto";
import type { Express, Request, Response } from "express";
import { HandoffError, signHandoff, verifyHandoff } from "./handoff.js";
import { MemoryNonceCache } from "./nonce.js";
import { decryptState, encryptState, StateError } from "./state.js";
import type {
  EntraProfile,
  MountOptions,
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

/**
 * Wire the preview-aware Entra flow onto an Express app. Idempotent for a
 * given `app` instance: caller must not call twice.
 */
export function mountEntraAuth(app: Express, options: MountOptions): void {
  const routes: RouteConfig = { ...DEFAULT_ROUTES, ...options.routes };
  const scopes = options.scopes ?? DEFAULT_SCOPES;
  const handoffTtl = options.handoffTtlSeconds ?? 60;
  const stateTtl = options.stateTtlSeconds ?? 600;
  const now = options.now ?? (() => Date.now());
  const nonceCache: NonceCache = options.nonceCache ?? new MemoryNonceCache(now);
  const previewPattern =
    options.previewOriginPattern ?? defaultPreviewOriginPattern(options.redirectUri);
  const prodHost = new URL(options.redirectUri).host;
  // MSAL loads lazily via top-level await once, then reused for every request.
  const msalPromise: Promise<MsalLike> = options.msalClient
    ? Promise.resolve(options.msalClient)
    : createDefaultMsal(options);

  app.get(routes.login, async (req, res) => {
    const returnTo = safeReturnTo(readQuery(req, "returnTo"));
    // Preview pod: bounce to prod's /login with target.
    if (options.prodAuthOrigin) {
      const target = `${req.protocol}://${req.get("host")}`;
      const url = new URL(routes.login, options.prodAuthOrigin);
      url.searchParams.set("target", target);
      url.searchParams.set("returnTo", returnTo);
      res.redirect(302, url.toString());
      return;
    }
    // Prod pod: could be direct-prod OR a preview bounce. `target` decides.
    let targetHost = prodHost;
    const target = readQuery(req, "target");
    if (target) {
      if (!isAllowedPreviewOrigin(target, previewPattern)) {
        res.status(400).send("target origin not allowed");
        return;
      }
      targetHost = new URL(target).host;
    }
    const csrf = randomBytes(16).toString("base64url");
    const codeVerifier = randomBytes(32).toString("base64url");
    const codeChallenge = createHash("sha256")
      .update(codeVerifier)
      .digest("base64url");
    const state = encryptState(
      { csrf, codeVerifier, targetHost, returnTo },
      options.handoffSecret,
      { now },
    );
    let authUrl: string;
    try {
      const msal = await msalPromise;
      authUrl = await msal.getAuthCodeUrl({
        scopes,
        redirectUri: options.redirectUri,
        state,
        codeChallenge,
        codeChallengeMethod: "S256",
        ...(options.authorizeExtras ?? {}),
      });
    } catch (err) {
      res.status(500).send("failed to start login");
      return;
    }
    res.redirect(302, authUrl);
  });

  app.get(routes.callback, async (req, res) => {
    // Callback only reachable on prod host (that's where the redirect URI
    // points). Guard against misroute.
    if (req.get("host") !== prodHost) {
      res.status(400).send("callback must run on prod host");
      return;
    }
    const code = readQuery(req, "code");
    const stateStr = readQuery(req, "state");
    if (!code || !stateStr) {
      const err = readQuery(req, "error");
      const desc = readQuery(req, "error_description");
      res.status(400).send(err ? `${err}: ${desc ?? ""}` : "missing code or state");
      return;
    }
    let payload;
    try {
      payload = decryptState(stateStr, options.handoffSecret, {
        ttlSeconds: stateTtl,
        now,
      });
    } catch (err) {
      if (err instanceof StateError) {
        res.status(400).send(`state ${err.code}`);
        return;
      }
      res.status(500).send("state decrypt failed");
      return;
    }
    let tokens;
    try {
      const msal = await msalPromise;
      tokens = await msal.acquireTokenByCode({
        code,
        scopes,
        redirectUri: options.redirectUri,
        codeVerifier: payload.codeVerifier,
      });
    } catch {
      res.status(400).send("token exchange failed");
      return;
    }
    let profile = extractProfile(tokens.idTokenClaims);
    if (!profile) {
      res.status(400).send("no email in id token");
      return;
    }
    if (options.enrichProfile) {
      try {
        profile = await options.enrichProfile(profile, tokens.accessToken);
      } catch {
        res.status(500).send("profile enrichment failed");
        return;
      }
    }
    const returnTo = safeReturnTo(payload.returnTo);
    if (payload.targetHost === prodHost) {
      // Direct-prod login.
      try {
        const override = await options.onLogin(profile, req, returnTo);
        res.redirect(302, override ? safeReturnTo(override) : returnTo);
      } catch {
        res.status(500).send("session setup failed");
      }
      return;
    }
    // Preview handoff.
    const token = signHandoff(
      {
        profile,
        targetHost: payload.targetHost,
        returnTo,
        ttlSeconds: handoffTtl,
        now,
      },
      options.handoffSecret,
    );
    const handoffUrl = new URL(routes.handoff, `https://${payload.targetHost}`);
    handoffUrl.searchParams.set("t", token);
    res.redirect(302, handoffUrl.toString());
  });

  app.get(routes.handoff, async (req, res) => {
    const token = readQuery(req, "t");
    if (!token) {
      res.status(400).send("missing handoff token");
      return;
    }
    const expectedTargetHost = req.get("host") ?? "";
    try {
      const payload = verifyHandoff(
        {
          token,
          expectedTargetHost,
          now,
          markNonceUsed: (n, ttl) => nonceCache.markUsed(n, ttl),
        },
        options.handoffSecret,
      );
      const returnTo = safeReturnTo(payload.returnTo);
      const override = await options.onLogin(payload.profile, req, returnTo);
      res.redirect(302, override ? safeReturnTo(override) : returnTo);
    } catch (err) {
      if (err instanceof HandoffError) {
        res.status(400).send(`handoff ${err.code}`);
        return;
      }
      res.status(500).send("handoff failed");
    }
  });
}

function readQuery(req: Request, key: string): string | undefined {
  const v = req.query[key];
  if (typeof v === "string") return v;
  return undefined;
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

async function createDefaultMsal(options: MountOptions): Promise<MsalLike> {
  // Dynamic import so the peer dep is only loaded when actually needed —
  // tests inject their own client via `msalClient` and never hit this path.
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
