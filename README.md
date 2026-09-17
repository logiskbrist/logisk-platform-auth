# logisk-platform-auth

Preview-aware **Entra ID** (Azure AD) auth broker for the Logiskbrist platform.

## Why

Every app that logs in with Entra registers its callback URL as a **redirect URI** in the app registration. When we spin up a `testversjon` (preview PR) at `https://<slug>-<app>.apps.godtbrod.no`, that URL isn't registered — login fails with `AADSTS50011`. Registering per-PR URIs runs into the 100-URI cap, force-closed-PR cleanup gaps, and a lost-update race on registrations shared across multiple apps.

This package solves it with **one redirect URI per app** (the prod host) and a handoff step:

1. Preview starts login → bounces to prod host's `/login?returnTo=<preview>`
2. Prod host runs the Entra code exchange (one redirect URI, always matches)
3. Prod host signs a short-lived JWT with the profile + preview host + nonce
4. 302 to `https://<preview>/handoff?token=…`
5. Preview verifies JWT, calls your `onLogin(profile, req)` hook, sets its own session cookie

No per-PR Entra edits. No race. No 100-URI cap. Prod login continues to work directly without the bounce.

## Install

```bash
npm install github:logiskbrist/logisk-platform-auth#v1.0.0
```

## Usage

```ts
import express from "express";
import session from "express-session";
import { mountEntraAuth } from "@logiskbrist/logisk-platform-auth";

const app = express();
app.set("trust proxy", 1);
app.use(session({ /* your session config */ }));

mountEntraAuth(app, {
  tenantId: process.env.AZURE_TENANT_ID!,
  clientId: process.env.AZURE_CLIENT_ID!,
  clientSecret: process.env.AZURE_CLIENT_SECRET!,
  redirectUri: process.env.ENTRA_REDIRECT_URI!,      // e.g. https://<app>.apps.<domain>/api/auth/microsoft/callback
  prodAuthOrigin: process.env.PROD_AUTH_ORIGIN,      // preview pods only; unset on prod
  handoffSecret: process.env.PREVIEW_HANDOFF_SECRET!,
  routes: {
    login: "/api/auth/microsoft/login",
    callback: "/api/auth/microsoft/callback",
    handoff: "/api/auth/microsoft/handoff",
  },
  scopes: ["openid", "profile", "email", "User.Read"],
  async onLogin(profile, req) {
    // Look up / provision the user, then set your session however the app wants.
    // Return the URL the browser should land on after login.
    req.session.user = await findOrCreateUser(profile);
    return "/";
  },
});
```

## Environment

| Variable | Where | Meaning |
| --- | --- | --- |
| `AZURE_TENANT_ID` | prod + preview | Entra tenant |
| `AZURE_CLIENT_ID` | prod + preview | App registration ID |
| `AZURE_CLIENT_SECRET` | prod + preview | App registration secret |
| `ENTRA_REDIRECT_URI` | prod + preview | The prod host's callback URL, registered in Entra. **Same value in every pod of the same app.** |
| `PROD_AUTH_ORIGIN` | preview only | e.g. `https://<app>.apps.<domain>` — origin the preview bounces login through |
| `PREVIEW_HANDOFF_SECRET` | prod + preview | HS256 signing key for the handoff JWT. **Same value in every pod of the same app.** |

## Entra setup

Register **one** redirect URI in your app registration:

```
https://<app>.apps.<domain>/api/auth/microsoft/callback
```

That's it. No per-PR URIs, ever.

## Security

- Handoff JWT: HS256, 60 s TTL, binds `target_host` to the preview URL
- Single-use `nonce` (per-pod cache) — replays inside the TTL are rejected
- `returnTo` restricted to origins the prod pod has been told about via `previewOriginPattern` (defaults to same registrable domain + subdomains)
- Session cookie is set by the preview pod on its own host — no cross-domain cookies
