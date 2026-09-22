// Orchestrator for POST /api/enrich. The actual per-target logic lives in
// emailEnrichment.ts / urlEnrichment.ts / groq.ts — this file's only job is
// to extract targets, fan out to those three concerns in parallel, cache
// the result, and shape the response. (Previously this was one ~480-line
// file; split for readability, not behavior change — see each extracted
// file's own header comment.)

import { extractEmails, extractUrls } from "../src/lib/extract";
import { EmailEnrichment, EnrichResponse, UrlEnrichment } from "../src/lib/types";
import { apiLimiter } from "../src/lib/rateLimit";
import { analyzeWithGroq } from "./groq";
import { enrichEmail } from "./emailEnrichment";
import { enrichUrl } from "./urlEnrichment";
import { isRawIp } from "./httpUtil";
import { getCached, setCached } from "./enrichCache";

export async function handleEnrich(text: string): Promise<EnrichResponse> {
  const cached = getCached(text);
  if (cached) return cached;

  const emails = extractEmails(text).slice(0, 5);
  const urls = extractUrls(text).slice(0, 5);

  // AI analysis runs over the whole message, independent of whether any
  // email/URL was found — it's the one enrichment that applies even to a
  // scam message with no extractable targets at all.
  const [settledEmails, settledUrls, groqResult] = await Promise.all([
    Promise.allSettled(emails.map(enrichEmail)),
    Promise.allSettled(urls.map(enrichUrl)),
    analyzeWithGroq(text),
  ]);

  const finalEmails: EmailEnrichment[] = settledEmails.map((item, idx) =>
    item.status === "fulfilled"
      ? item.value
      : { email: emails[idx], domain: emails[idx].split("@")[1] || "", error: "unavailable" }
  );

  const finalUrls: UrlEnrichment[] = settledUrls.map((item, idx) =>
    item.status === "fulfilled"
      ? item.value
      : { url: urls[idx], isIp: isRawIp(urls[idx]), error: "unavailable" }
  );

  const response: EnrichResponse = {
    emails: finalEmails,
    urls: finalUrls,
  };
  if (groqResult.analysis) {
    response.aiAnalysis = groqResult.analysis;
  } else if (groqResult.rateLimited || groqResult.error) {
    response.aiAnalysis = {
      verdict: "uncertain",
      confidence: "low",
      scoreAdjustment: 0,
      reasoning: "",
      languageDetected: "unknown",
      promptInjectionAttempt: false,
      model: "openai/gpt-oss-120b",
      rateLimited: groqResult.rateLimited,
      error: groqResult.error,
    };
  }

  // Only cache a result that actually reflects live data (or a text with no
  // targets at all) — never cache a rate-limited/error snapshot, so the
  // next identical scan gets a fresh attempt rather than repeating a
  // transient failure for the full TTL.
  const hadTransientFailure =
    response.aiAnalysis?.rateLimited ||
    response.aiAnalysis?.error ||
    finalEmails.some((e) => e.virustotalRateLimited) ||
    finalUrls.some((u) => u.virustotal?.status === "rate_limited");
  if (!hadTransientFailure) setCached(text, response);

  return response;
}

// Standard serverless export (Vercel / Cloud Function / Node 20 handler)
//
// NOTE on rate limiting here: apiLimiter is an in-process memory store. A
// real serverless platform does not guarantee the same process (or memory)
// handles the next request, so this check is a best-effort courtesy, not a
// guarantee, in that deployment shape — see src/lib/rateLimit.ts's header
// comment. It's a full guarantee for the Vite dev-server path below and for
// any deployment that runs this as one long-lived Node process.
export default async function handler(req: any, res: any) {
  if (req.method !== "POST") {
    res.setHeader?.("Allow", "POST");
    return res.status ? res.status(405).json({ error: "Method Not Allowed" }) : null;
  }

  const ip = req.headers?.["x-forwarded-for"]?.toString().split(",")[0].trim() || req.socket?.remoteAddress || "unknown";
  if (!apiLimiter.tryConsume(ip)) {
    const retryAfterSec = Math.ceil(apiLimiter.retryAfterMs(ip) / 1000);
    res.setHeader?.("Retry-After", String(retryAfterSec));
    return res.status
      ? res.status(429).json({ error: "rate_limited", retryAfterSeconds: retryAfterSec })
      : res.end(JSON.stringify({ error: "rate_limited", retryAfterSeconds: retryAfterSec }));
  }

  try {
    let body = req.body;
    if (typeof body === "string") {
      try {
        body = JSON.parse(body);
      } catch {
        // ignore
      }
    }
    const text = body?.text || "";
    const response = await handleEnrich(text);
    return res.status ? res.status(200).json(response) : res.end(JSON.stringify(response));
  } catch (err: any) {
    console.error("Enrich handler error:", err);
    return res.status
      ? res.status(200).json({ emails: [], urls: [] })
      : res.end(JSON.stringify({ emails: [], urls: [] }));
  }
}
