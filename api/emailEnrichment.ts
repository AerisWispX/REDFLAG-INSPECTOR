// Single-email enrichment: EmailRep, Disify, WHOIS, VirusTotal.
// Extracted from api/enrich.ts so that file is an orchestrator, not a
// 480-line everything-file — this one has exactly one job.

import { EmailEnrichment } from "../src/lib/types";
import { fetchWithTimeout, extractFlaggedBy } from "./httpUtil";
import { vtLimiter } from "../src/lib/rateLimit";

export async function enrichEmail(email: string): Promise<EmailEnrichment> {
  const domain = email.split("@")[1] || "";
  const result: EmailEnrichment = { email, domain };

  const emailRepKey = process.env.EMAILREP_KEY;
  const whoisApiKey = process.env.WHOIS_API_KEY;
  const virusTotalKey = process.env.VIRUSTOTAL_KEY;

  const subtasks: Promise<void>[] = [];

  // (a) EmailRep.io
  subtasks.push(
    (async () => {
      try {
        const headers: Record<string, string> = { "User-Agent": "RedFlag-Inspector/1.0" };
        if (emailRepKey) headers["Key"] = emailRepKey;
        const resp = await fetchWithTimeout(`https://emailrep.io/${encodeURIComponent(email)}`, { headers });
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
  subtasks.push(
    (async () => {
      try {
        const resp = await fetchWithTimeout(`https://disify.com/api/email/${encodeURIComponent(email)}`);
        if (resp.ok) {
          const data = await resp.json();
          result.disify = { disposable: Boolean(data.disposable), dnsValid: Boolean(data.dns) };
        }
      } catch {
        // Keep non-blocking
      }
    })()
  );

  // (c) WhoisXmlApi (only if WHOIS_API_KEY is present)
  if (whoisApiKey && domain) {
    subtasks.push(
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
              domainAgeDays = Math.max(0, Math.floor((Date.now() - new Date(createdDate).getTime()) / 86400000));
            }
            result.whois = { createdDate, domainAgeDays };
          }
        } catch {
          // Keep non-blocking
        }
      })()
    );
  }

  // (d) VirusTotal domain report — gated by vtLimiter first: VT's free tier
  // is 4 req/min, shared with the URL lookups, so we fail fast and honestly
  // rather than silently dropping the result if quota's already spent.
  if (virusTotalKey && domain) {
    subtasks.push(
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
                ? Math.max(0, Math.floor((Date.now() - creationUnix * 1000) / 86400000))
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

  await Promise.allSettled(subtasks);

  // If no enrichment service returned data, mark unavailable — but a VT
  // rate-limit is informative, not a blank result, so don't mask it.
  if (!result.emailrep && !result.disify && !result.whois && !result.virustotal && !result.virustotalRateLimited) {
    result.error = "unavailable";
  }

  return result;
}
