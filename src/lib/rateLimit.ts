// Shared in-memory rate limiters.
//
// Two independent uses:
//  1. `vtLimiter` — VirusTotal's free tier is 4 requests/minute (verified
//     live). Every VT call anywhere in the app goes through this so a scan
//     that would exceed the quota fails fast with a clear "rate limited"
//     state instead of the request silently coming back empty.
//  2. `apiLimiter(ip)` — protects THIS app's own /api/enrich endpoint from
//     abuse. Without it, anyone hitting the endpoint repeatedly drains the
//     operator's EmailRep/WHOIS/SafeBrowsing/AbuseIPDB/VirusTotal quotas —
//     all of which are the operator's own paid or rate-limited keys.
//
// Both are process-memory sliding windows: correct and sufficient for a
// single long-running Node process (`node server.js`-style, or this Vite
// dev server). A true serverless deployment (Vercel/Cloud Functions) does
// NOT share memory across invocations, so this alone is not sufficient
// there — you'd need an external store (Upstash Redis, Cloudflare KV, a
// database row with a timestamp) for the same guarantee in that
// environment. Documented here rather than silently assumed to work.

class SlidingWindowLimiter {
  private hits = new Map<string, number[]>();
  constructor(
    private readonly limit: number,
    private readonly windowMs: number
  ) {}

  /** Returns true if this call is allowed (and records it); false if over the limit. */
  tryConsume(key: string): boolean {
    const now = Date.now();
    const existing = this.hits.get(key) || [];
    const recent = existing.filter((t) => now - t < this.windowMs);
    if (recent.length >= this.limit) {
      this.hits.set(key, recent);
      return false;
    }
    recent.push(now);
    this.hits.set(key, recent);
    return true;
  }

  /** Milliseconds until the oldest hit in the current window expires (0 if not limited). */
  retryAfterMs(key: string): number {
    const now = Date.now();
    const existing = (this.hits.get(key) || []).filter((t) => now - t < this.windowMs);
    if (existing.length < this.limit) return 0;
    return Math.max(0, this.windowMs - (now - existing[0]));
  }
}

// VirusTotal free tier: 4 requests/minute, shared across every VT call this
// process makes (domain lookups + URL lookups + submits + analysis polls
// all count against the same quota on VT's side).
export const vtLimiter = new SlidingWindowLimiter(4, 60_000);

// This app's own API: generous enough for normal use (a handful of scans in
// a browsing session) while still blocking a scripted hammer. Keyed by
// caller IP.
export const apiLimiter = new SlidingWindowLimiter(10, 60_000);

// Groq (openai/gpt-oss-120b): verified live via response headers —
// 1000 requests/min and 8000 tokens/min on this key's current tier. Each
// analysis call here runs ~550-750 tokens total, so tokens are the binding
// constraint at roughly ~11 calls/min; kept at 10/min to stay under both
// with margin, well above VT's 4/min but still a real cap.
export const groqLimiter = new SlidingWindowLimiter(10, 60_000);

// Community reports (section 08): separate, tighter limits than the general
// apiLimiter — submitting/confirming a report writes to the shared JSON
// store everyone sees, so the cost of abuse here is spam in a PUBLIC feed,
// not just wasted API quota. Keyed by caller IP.
export const reportSubmitLimiter = new SlidingWindowLimiter(3, 10 * 60_000); // 3 reports / 10 min
export const reportConfirmLimiter = new SlidingWindowLimiter(20, 60_000); // 20 confirms / min
