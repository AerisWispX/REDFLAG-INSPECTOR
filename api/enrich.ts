import { extractEmails, extractUrls } from "../src/lib/extract";
import { EmailEnrichment, EnrichResponse, UrlEnrichment } from "../src/lib/types";
import { vtLimiter, apiLimiter } from "../src/lib/rateLimit";
import { analyzeWithGroq } from "./groq";

// Timeout wrapper helper
function fetchWithTimeout(url: string, options: RequestInit = {}, timeoutMs = 5000): Promise<Response> {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeoutMs);
  return fetch(url, { ...options, signal: controller.signal }).finally(() => clearTimeout(id));
}

function isRawIp(host: string): boolean {
  return /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host);
}

// VirusTotal v3 identifies a URL by the base64url (no padding) of the raw URL string.
function vtUrlId(url: string): string {
  return Buffer.from(url).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// VT's `last_analysis_results` is a map of engine name -> { category, result, ... }.
// We only care about the engines that actually flagged it, capped to keep the
// response (and the UI list) compact.
function extractFlaggedBy(analysisResults: Record<string, { category?: string }> | undefined): string[] {
  if (!analysisResults) return [];
  return Object.entries(analysisResults)
    .filter(([, v]) => v?.category === "malicious" || v?.category === "suspicious")
    .map(([engine]) => engine)
    .slice(0, 8);
}

export async function handleEnrich(text: string): Promise<EnrichResponse> {
  const emails = extractEmails(text).slice(0, 5);
  const urls = extractUrls(text).slice(0, 5);

  const emailRepKey = process.env.EMAILREP_KEY;
  const whoisApiKey = process.env.WHOIS_API_KEY;
  const safeBrowsingKey = process.env.SAFE_BROWSING_KEY;
  const abuseIpdbKey = process.env.ABUSEIPDB_KEY;
  const virusTotalKey = process.env.VIRUSTOTAL_KEY;

  // 1. Process Emails in parallel
  const emailPromises = emails.map(async (email): Promise<EmailEnrichment> => {
    const domain = email.split("@")[1] || "";
    const result: EmailEnrichment = { email, domain };

    const emailSubtasks: Promise<void>[] = [];

    // (a) EmailRep.io
    emailSubtasks.push(
      (async () => {
        try {
          const headers: Record<string, string> = {
            "User-Agent": "RedFlag-Inspector/1.0",
          };
          if (emailRepKey) {
            headers["Key"] = emailRepKey;
          }
          const resp = await fetchWithTimeout(`https://emailrep.io/${encodeURIComponent(email)}`, {
            headers,
          });
          if (resp.ok) {
            const data = await resp.json();
            result.emailrep = {
              reputation: data.reputation || "none",
              suspicious: Boolean(data.suspicious),
              newDomain: Boolean(data.details?.new_domain),
              daysSinceDomainCreation: data.details?.days_since_domain_creation ?? null,
              freeProvider: Boolean(data.details?.free_provider),
              disposable: Boolean(data.details?.disposable),
              credentialsLeaked: Boolean(data.details?.credentials_leaked),
            };
          }
        } catch {
          // Keep non-blocking
        }
      })()
    );

    // (b) Disify.com
    emailSubtasks.push(
      (async () => {
        try {
          const resp = await fetchWithTimeout(`https://disify.com/api/email/${encodeURIComponent(email)}`);
          if (resp.ok) {
            const data = await resp.json();
            result.disify = {
              disposable: Boolean(data.disposable),
              dnsValid: Boolean(data.dns),
            };
          }
        } catch {
          // Keep non-blocking
        }
      })()
    );

    // (c) WhoisXmlApi (only if WHOIS_API_KEY is present)
    if (whoisApiKey && domain) {
      emailSubtasks.push(
        (async () => {
          try {
            const whoisUrl = `https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=${encodeURIComponent(
              whoisApiKey
            )}&domainName=${encodeURIComponent(domain)}&outputFormat=JSON`;
            const resp = await fetchWithTimeout(whoisUrl);
            if (resp.ok) {
              const data = await resp.json();
              const rec = data?.WhoisRecord;
              const createdDate = rec?.createdDate || rec?.registryData?.createdDate || null;
              let domainAgeDays: number | null = null;
              if (createdDate) {
                const diffTime = Date.now() - new Date(createdDate).getTime();
                domainAgeDays = Math.max(0, Math.floor(diffTime / (1000 * 60 * 60 * 24)));
              }
              result.whois = {
                createdDate,
                domainAgeDays,
              };
            }
          } catch {
            // Keep non-blocking
          }
        })()
      );
    }

    // (d) VirusTotal domain report — reputation + engine votes + a second,
    // independent source of domain-registration age alongside WHOIS. Gated
    // by vtLimiter first: VT's free tier is 4 req/min, shared with the URL
    // lookups below, so we fail fast and honestly rather than silently
    // dropping the result if the quota's already spent this minute.
    if (virusTotalKey && domain) {
      emailSubtasks.push(
        (async () => {
          if (!vtLimiter.tryConsume("virustotal")) {
            result.virustotalRateLimited = true;
            return;
          }
          try {
            const resp = await fetchWithTimeout(
              `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(domain)}`,
              { headers: { "x-apikey": virusTotalKey } },
              6000
            );
            if (resp.ok) {
              const data = await resp.json();
              const attrs = data?.data?.attributes;
              if (attrs) {
                const creationUnix = attrs.creation_date as number | undefined;
                const creationDate = creationUnix ? new Date(creationUnix * 1000).toISOString() : null;
                const domainAgeDays = creationUnix
                  ? Math.max(0, Math.floor((Date.now() - creationUnix * 1000) / (1000 * 60 * 60 * 24)))
                  : null;
                result.virustotal = {
                  reputation: attrs.reputation ?? 0,
                  maliciousVotes: attrs.last_analysis_stats?.malicious ?? 0,
                  creationDate,
                  domainAgeDays,
                  flaggedBy: extractFlaggedBy(attrs.last_analysis_results),
                };
              }
            } else if (resp.status === 429) {
              result.virustotalRateLimited = true;
            }
          } catch {
            // Non-blocking
          }
        })()
      );
    }

    await Promise.allSettled(emailSubtasks);

    // If no enrichment service returned data, mark unavailable — but a VT
    // rate-limit is informative, not a blank result, so don't mask it.
    if (!result.emailrep && !result.disify && !result.whois && !result.virustotal && !result.virustotalRateLimited) {
      result.error = "unavailable";
    }

    return result;
  });

  // 2. Process URLs in parallel
  const urlPromises = urls.map(async (rawUrl): Promise<UrlEnrichment> => {
    let hostname = "";
    try {
      hostname = new URL(rawUrl).hostname;
    } catch {
      hostname = rawUrl;
    }
    const isIp = isRawIp(hostname);
    const result: UrlEnrichment = { url: rawUrl, isIp };

    const urlSubtasks: Promise<void>[] = [];

    // (a) Google Safe Browsing
    if (safeBrowsingKey) {
      urlSubtasks.push(
        (async () => {
          try {
            const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(
              safeBrowsingKey
            )}`;
            const payload = {
              client: { clientId: "redflag-inspector", clientVersion: "1.0.0" },
              threatInfo: {
                threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                platformTypes: ["ANY_PLATFORM"],
                threatEntryTypes: ["URL"],
                threatEntries: [{ url: rawUrl }],
              },
            };
            const resp = await fetchWithTimeout(endpoint, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify(payload),
            });
            if (resp.ok) {
              const data = await resp.json();
              const matches = data.matches || [];
              result.safeBrowsing = {
                threatMatch: matches.length > 0,
                threatTypes: matches.map((m: { threatType: string }) => m.threatType),
              };
            }
          } catch {
            // Non-blocking
          }
        })()
      );
    }

    // (b) AbuseIPDB (only if IP and key available)
    if (isIp && abuseIpdbKey) {
      urlSubtasks.push(
        (async () => {
          try {
            const abuseUrl = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(
              hostname
            )}&maxAgeInDays=90`;
            const resp = await fetchWithTimeout(abuseUrl, {
              headers: {
                Key: abuseIpdbKey,
                Accept: "application/json",
              },
            });
            if (resp.ok) {
              const data = await resp.json();
              result.abuseIpdb = {
                abuseConfidenceScore: data?.data?.abuseConfidenceScore ?? 0,
              };
            }
          } catch {
            // Non-blocking
          }
        })()
      );
    }

    // (c) VirusTotal URL report. VT identifies URLs by a base64url id, so we
    // GET the existing report first (most URLs someone would paste here have
    // been scanned before); if VT has never seen it (404), we submit it for
    // analysis and poll once, briefly — a brand-new URL may still come back
    // "queued" rather than "completed" within our time budget, which is
    // reported honestly rather than blocked on indefinitely.
    if (virusTotalKey) {
      urlSubtasks.push(
        (async () => {
          const id = vtUrlId(rawUrl);
          // The GET-report call always counts against the quota; reserve one
          // slot for it up front. The submit+poll path (404 branch) needs up
          // to two more, checked individually below so a URL VT already
          // knows about never pays that cost.
          if (!vtLimiter.tryConsume("virustotal")) {
            result.virustotal = {
              status: "rate_limited",
              maliciousVotes: 0,
              suspiciousVotes: 0,
              totalEngines: 0,
              permalink: `https://www.virustotal.com/gui/url/${id}`,
            };
            return;
          }
          try {
            const headers = { "x-apikey": virusTotalKey };
            const resp = await fetchWithTimeout(`https://www.virustotal.com/api/v3/urls/${id}`, { headers }, 6000);

            if (resp.status === 404) {
              if (!vtLimiter.tryConsume("virustotal")) {
                result.virustotal = {
                  status: "rate_limited",
                  maliciousVotes: 0,
                  suspiciousVotes: 0,
                  totalEngines: 0,
                  permalink: `https://www.virustotal.com/gui/url/${id}`,
                };
                return;
              }
              const submit = await fetchWithTimeout(
                "https://www.virustotal.com/api/v3/urls",
                {
                  method: "POST",
                  headers: { ...headers, "Content-Type": "application/x-www-form-urlencoded" },
                  body: new URLSearchParams({ url: rawUrl }).toString(),
                },
                6000
              );
              if (submit.ok) {
                const submitData = await submit.json();
                const analysisId = submitData?.data?.id;
                if (analysisId && vtLimiter.tryConsume("virustotal")) {
                  await new Promise((r) => setTimeout(r, 2500));
                  const analysis = await fetchWithTimeout(
                    `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
                    { headers },
                    5000
                  );
                  if (analysis.ok) {
                    const analysisData = await analysis.json();
                    const a = analysisData?.data?.attributes;
                    if (a?.status === "completed") {
                      const stats = a.stats || {};
                      const total = Object.values(stats).reduce((s: number, n: any) => s + (Number(n) || 0), 0);
                      result.virustotal = {
                        status: "completed",
                        maliciousVotes: stats.malicious ?? 0,
                        suspiciousVotes: stats.suspicious ?? 0,
                        totalEngines: total,
                        permalink: `https://www.virustotal.com/gui/url/${id}`,
                        flaggedBy: extractFlaggedBy(a.results),
                      };
                    } else {
                      result.virustotal = {
                        status: "queued",
                        maliciousVotes: 0,
                        suspiciousVotes: 0,
                        totalEngines: 0,
                        permalink: `https://www.virustotal.com/gui/url/${id}`,
                      };
                    }
                  }
                } else if (analysisId) {
                  // Submitted successfully but no quota left to poll it this call.
                  result.virustotal = {
                    status: "queued",
                    maliciousVotes: 0,
                    suspiciousVotes: 0,
                    totalEngines: 0,
                    permalink: `https://www.virustotal.com/gui/url/${id}`,
                  };
                }
              }
            } else if (resp.ok) {
              const data = await resp.json();
              const attrs = data?.data?.attributes;
              const stats = attrs?.last_analysis_stats || {};
              const total = Object.values(stats).reduce((s: number, n: any) => s + (Number(n) || 0), 0);
              result.virustotal = {
                status: "completed",
                maliciousVotes: stats.malicious ?? 0,
                suspiciousVotes: stats.suspicious ?? 0,
                totalEngines: total,
                permalink: `https://www.virustotal.com/gui/url/${id}`,
                flaggedBy: extractFlaggedBy(attrs.last_analysis_results),
              };
            } else if (resp.status === 429) {
              result.virustotal = {
                status: "rate_limited",
                maliciousVotes: 0,
                suspiciousVotes: 0,
                totalEngines: 0,
                permalink: `https://www.virustotal.com/gui/url/${id}`,
              };
            }
          } catch {
            // Non-blocking
          }
        })()
      );
    }

    await Promise.allSettled(urlSubtasks);

    // If no enrichment service returned data, mark unavailable
    if (!result.safeBrowsing && !result.abuseIpdb && !result.virustotal) {
      result.error = "unavailable";
    }

    return result;
  });

  // AI analysis runs over the whole message, independent of whether any
  // email/URL was found — it's the one enrichment that applies even to a
  // scam message with no extractable targets at all.
  const [settledEmails, settledUrls, groqResult] = await Promise.all([
    Promise.allSettled(emailPromises),
    Promise.allSettled(urlPromises),
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
