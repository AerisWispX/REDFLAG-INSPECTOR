// Small shared helpers used by both emailEnrichment.ts and urlEnrichment.ts.
// Split out of what used to be one large api/enrich.ts so each concern has
// its own short, single-purpose file.

/** Fetch with a hard timeout — every external call in this app uses this, never a bare fetch(). */
export function fetchWithTimeout(url: string, options: RequestInit = {}, timeoutMs = 5000): Promise<Response> {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeoutMs);
  return fetch(url, { ...options, signal: controller.signal }).finally(() => clearTimeout(id));
}

export function isRawIp(host: string): boolean {
  return /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host);
}

/** VirusTotal v3 identifies a URL by the base64url (no padding) of the raw URL string. */
export function vtUrlId(url: string): string {
  return Buffer.from(url).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * VT's `last_analysis_results` is a map of engine name -> { category, result, ... }.
 * We only care about the engines that actually flagged it, capped to keep the
 * response (and the UI list) compact.
 */
export function extractFlaggedBy(analysisResults: Record<string, { category?: string }> | undefined): string[] {
  if (!analysisResults) return [];
  return Object.entries(analysisResults)
    .filter(([, v]) => v?.category === "malicious" || v?.category === "suspicious")
    .map(([engine]) => engine)
    .slice(0, 8);
}
