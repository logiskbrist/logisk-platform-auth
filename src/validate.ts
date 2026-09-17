/**
 * Rejects anything that isn't a same-origin path.
 *
 * Accepts: `/`, `/some/path`, `/x?y=1`, `/x#anchor`.
 * Rejects: absolute URLs, protocol-relative (`//evil`), missing leading slash.
 */
export function safeReturnTo(input: string | undefined | null): string {
  if (!input || typeof input !== "string") return "/";
  if (!input.startsWith("/")) return "/";
  if (input.startsWith("//")) return "/";
  if (input.startsWith("/\\")) return "/";
  return input;
}

/**
 * Build a default preview-origin regex from the prod redirect URI.
 *
 * `https://foo.apps.gb.logiskbrist.no/...` → matches `https://<x>.apps.gb.logiskbrist.no`
 * for any single-label `<x>`. Bounces to hosts outside that pattern are refused.
 */
export function defaultPreviewOriginPattern(redirectUri: string): RegExp {
  const u = new URL(redirectUri);
  const host = u.hostname;
  const dot = host.indexOf(".");
  const suffix = dot === -1 ? host : host.slice(dot + 1);
  // Anchor and escape suffix.
  const esc = suffix.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`^https://[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.${esc}$`, "i");
}

/**
 * True when `target` is a syntactically valid `https://<host>` origin whose
 * host matches the allowed pattern.
 */
export function isAllowedPreviewOrigin(
  target: string,
  pattern: RegExp,
): boolean {
  let u: URL;
  try {
    u = new URL(target);
  } catch {
    return false;
  }
  if (u.protocol !== "https:") return false;
  if (u.pathname !== "/" && u.pathname !== "") return false;
  if (u.search || u.hash) return false;
  const origin = `${u.protocol}//${u.host}`;
  return pattern.test(origin);
}
