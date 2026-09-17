import { describe, expect, it } from "vitest";
import {
  defaultPreviewOriginPattern,
  isAllowedPreviewOrigin,
  safeReturnTo,
} from "./validate.js";

describe("safeReturnTo", () => {
  it("accepts a simple path", () => {
    expect(safeReturnTo("/dashboard")).toBe("/dashboard");
  });

  it("accepts an empty path as root", () => {
    expect(safeReturnTo(undefined)).toBe("/");
    expect(safeReturnTo("")).toBe("/");
  });

  it("rejects absolute URLs", () => {
    expect(safeReturnTo("https://evil.com/path")).toBe("/");
  });

  it("rejects protocol-relative", () => {
    expect(safeReturnTo("//evil.com/path")).toBe("/");
  });

  it("rejects backslash tricks", () => {
    expect(safeReturnTo("/\\evil.com")).toBe("/");
  });

  it("accepts query and hash", () => {
    expect(safeReturnTo("/x?y=1#a")).toBe("/x?y=1#a");
  });
});

describe("defaultPreviewOriginPattern + isAllowedPreviewOrigin", () => {
  const prodUri = "https://deigverkstedet.apps.gb.logiskbrist.no/api/auth/microsoft/callback";
  const pattern = defaultPreviewOriginPattern(prodUri);

  it("accepts a preview under the same registrable domain", () => {
    expect(
      isAllowedPreviewOrigin(
        "https://pr-42-deigverkstedet.apps.gb.logiskbrist.no",
        pattern,
      ),
    ).toBe(true);
  });

  it("accepts the prod host itself (single label)", () => {
    expect(
      isAllowedPreviewOrigin(
        "https://deigverkstedet.apps.gb.logiskbrist.no",
        pattern,
      ),
    ).toBe(true);
  });

  it("rejects a different registrable domain", () => {
    expect(
      isAllowedPreviewOrigin("https://pr-42-x.apps.godtbrod.no", pattern),
    ).toBe(false);
    expect(
      isAllowedPreviewOrigin("https://evil.com", pattern),
    ).toBe(false);
  });

  it("rejects http (non-TLS)", () => {
    expect(
      isAllowedPreviewOrigin(
        "http://pr-42-deigverkstedet.apps.gb.logiskbrist.no",
        pattern,
      ),
    ).toBe(false);
  });

  it("rejects an origin carrying a path or query", () => {
    expect(
      isAllowedPreviewOrigin(
        "https://pr-42-deigverkstedet.apps.gb.logiskbrist.no/haha",
        pattern,
      ),
    ).toBe(false);
    expect(
      isAllowedPreviewOrigin(
        "https://pr-42-deigverkstedet.apps.gb.logiskbrist.no?x=1",
        pattern,
      ),
    ).toBe(false);
  });

  it("rejects malformed input", () => {
    expect(isAllowedPreviewOrigin("not-a-url", pattern)).toBe(false);
  });
});
