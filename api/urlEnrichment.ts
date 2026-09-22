// Single-URL enrichment: Google Safe Browsing, AbuseIPDB, VirusTotal.
// Extracted from api/enrich.ts — see emailEnrichment.ts's header comment
// for why this split happened.

import { UrlEnrichment } from "../src/lib/types";
import { fetchWithTimeout, isRawIp, vtUrlId, extractFlaggedBy } from "./httpUtil";
import { vtLimiter } from "../src/lib/rateLimit";

function rateLimitedVt(id: string): UrlEnrichment["virustotal"] {
  return {
    status: "rate_limited",
    maliciousVotes: 0,
    suspiciousVotes: 0,
    totalEngines: 0,
    permalink: `https://www.virustotal.com/gui/url/${id}`,
  };
}

export async function enrichUrl(rawUrl: string): Promise<UrlEnrichment> {
  let hostname = "";
  try {
    hostname = new URL(rawUrl).hostname;
  } catch {
    hostname = rawUrl;
  }
  const isIp = isRawIp(hostname);
  const result: UrlEnrichment = { url: rawUrl, isIp };

  const safeBrowsingKey = process.env.SAFE_BROWSING_KEY;
  const abuseIpdbKey = process.env.ABUSEIPDB_KEY;
  const virusTotalKey = process.env.VIRUSTOTAL_KEY;

  const subtasks: Promise<void>[] = [];

  // (a) Google Safe Browsing
  if (safeBrowsingKey) {
    subtasks.push(
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
    subtasks.push(
      (async () => {
        try {
          const abuseUrl = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(
            hostname
          )}&maxAgeInDays=90`;
          const resp = await fetchWithTimeout(abuseUrl, { headers: { Key: abuseIpdbKey, Accept: "application/json" } });
          if (resp.ok) {
            const data = await resp.json();
            result.abuseIpdb = { abuseConfidenceScore: data?.data?.abuseConfidenceScore ?? 0 };
          }
        } catch {
          // Non-blocking
        }
      })()
    );
  }

  // (c) VirusTotal URL report. GET the existing report first (most URLs
  // someone would paste here have been scanned before); if VT has never
  // seen it (404), submit it for analysis and poll once, briefly — a
  // brand-new URL may still come back "queued" rather than "completed"
  // within our time budget, reported honestly rather than blocked on
  // indefinitely.
  if (virusTotalKey) {
    subtasks.push(
      (async () => {
        const id = vtUrlId(rawUrl);
        if (!vtLimiter.tryConsume("virustotal")) {
          result.virustotal = rateLimitedVt(id);
          return;
        }
        try {
          const headers = { "x-apikey": virusTotalKey };
          const resp = await fetchWithTimeout(`https://www.virustotal.com/api/v3/urls/${id}`, { headers }, 6000);

          if (resp.status === 404) {
            if (!vtLimiter.tryConsume("virustotal")) {
              result.virustotal = rateLimitedVt(id);
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
            result.virustotal = rateLimitedVt(id);
          }
        } catch {
          // Non-blocking
        }
      })()
    );
  }

  await Promise.allSettled(subtasks);

  if (!result.safeBrowsing && !result.abuseIpdb && !result.virustotal) {
    result.error = "unavailable";
  }

  return result;
}
