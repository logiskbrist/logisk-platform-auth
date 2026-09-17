import type { NonceCache } from "./types.js";

/**
 * In-memory single-use nonce cache. Nonces are kept for their TTL and then
 * garbage-collected — a nonce reappearing after its TTL is not tracked, but
 * that doesn't matter because `verifyHandoff` will reject it as expired first.
 *
 * One instance per pod. Preview handoffs are short-lived (default 60 s) so
 * per-pod memory is fine — a replay from another pod's cache would still be
 * rejected on the pod that sees it first.
 */
export class MemoryNonceCache implements NonceCache {
  private store = new Map<string, number>();

  constructor(private readonly now: () => number = () => Date.now()) {}

  markUsed(nonce: string, ttlSeconds: number): boolean {
    this.evict();
    if (this.store.has(nonce)) return false;
    this.store.set(nonce, this.now() + ttlSeconds * 1000);
    return true;
  }

  private evict(): void {
    const t = this.now();
    for (const [k, exp] of this.store) {
      if (exp <= t) this.store.delete(k);
    }
  }

  /** Test-only: current tracked count. */
  get size(): number {
    return this.store.size;
  }
}
