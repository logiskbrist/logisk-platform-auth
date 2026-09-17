import { describe, expect, it } from "vitest";
import { MemoryNonceCache } from "./nonce.js";

describe("MemoryNonceCache", () => {
  it("accepts a nonce the first time", () => {
    const cache = new MemoryNonceCache();
    expect(cache.markUsed("abc", 60)).toBe(true);
  });

  it("rejects a replay within TTL", () => {
    const cache = new MemoryNonceCache();
    expect(cache.markUsed("abc", 60)).toBe(true);
    expect(cache.markUsed("abc", 60)).toBe(false);
  });

  it("garbage-collects expired entries", () => {
    let t = 1000;
    const cache = new MemoryNonceCache(() => t);
    cache.markUsed("a", 60);
    cache.markUsed("b", 60);
    expect(cache.size).toBe(2);
    t += 61_000;
    cache.markUsed("c", 60);
    // "a" and "b" were older than 60 s at the time "c" was marked → both evicted.
    expect(cache.size).toBe(1);
  });
});
