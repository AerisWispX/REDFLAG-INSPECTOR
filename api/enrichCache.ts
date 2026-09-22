// In-memory result cache for /api/enrich, keyed by a hash of the scanned
// text. Directly addresses a documented gap: previously every scan
// re-ran every enrichment call, even an identical message scanned twice in
// a row — real wasted latency and real wasted quota against VT's tight
// 4-req/min free-tier limit. A hit here skips every network call entirely.
//
// Deliberately NOT a persistence layer (unlike reportsStore.ts) — this is
// pure performance, safe to lose on restart, and safe to be
// process-local/not shared across instances (a cache miss just means "do
// the work again," never a correctness problem, unlike the rate limiters
// or the reports store).

import { EnrichResponse } from "../src/lib/types";
import { createHash } from "node:crypto";

interface CacheEntry {
  response: EnrichResponse;
  expiresAt: number;
}

const TTL_MS = 5 * 60_000; // 5 minutes — long enough to catch a re-scan/re-run within one session, short enough that live threat data doesn't go stale
const MAX_ENTRIES = 200; // hackathon-scale cap; oldest entries evicted first

const cache = new Map<string, CacheEntry>();

export function hashText(text: string): string {
  return createHash("sha256").update(text.trim()).digest("hex");
}

export function getCached(text: string): EnrichResponse | null {
  const key = hashText(text);
  const entry = cache.get(key);
  if (!entry) return null;
  if (Date.now() > entry.expiresAt) {
    cache.delete(key);
    return null;
  }
  return entry.response;
}

export function setCached(text: string, response: EnrichResponse): void {
  const key = hashText(text);
  if (cache.size >= MAX_ENTRIES && !cache.has(key)) {
    const oldestKey = cache.keys().next().value;
    if (oldestKey) cache.delete(oldestKey);
  }
  cache.set(key, { response, expiresAt: Date.now() + TTL_MS });
}
