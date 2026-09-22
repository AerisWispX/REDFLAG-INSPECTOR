// Shareable report links — no server storage.
//
// "Share report" encodes the finished scan (score, categories, hits,
// breakdown, a text preview, case ID, timestamp) as base64 JSON in the URL
// *fragment* (#share=...), not a query param and not a server-stored row:
//  - A fragment is never sent to the server on page load, so nothing about
//    the scanned message touches this app's backend or logs by sharing it.
//  - No database, no expiry policy, no "who can see this" question — the
//    link IS the data. Whoever has the link can decode it entirely
//    client-side, same as this tab does.
// Trade-off: the link is long (proportional to how much evidence was
// found) and anyone with it can read the full report, including the
// scanned-text preview — treat it like sharing the report text itself.

import { ScanResult } from "./types";

export interface SharedReport {
  caseId: string;
  timestamp: string;
  scannedTextPreview: string;
  scanResult: ScanResult;
}

function toBase64Url(json: string): string {
  const b64 =
    typeof window !== "undefined"
      ? window.btoa(unescape(encodeURIComponent(json)))
      : Buffer.from(json, "utf-8").toString("base64");
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromBase64Url(b64url: string): string {
  const b64 = b64url.replace(/-/g, "+").replace(/_/g, "/").padEnd(b64url.length + ((4 - (b64url.length % 4)) % 4), "=");
  return typeof window !== "undefined"
    ? decodeURIComponent(escape(window.atob(b64)))
    : Buffer.from(b64, "base64").toString("utf-8");
}

export function encodeShareLink(report: SharedReport): string {
  const json = JSON.stringify(report);
  const encoded = toBase64Url(json);
  const { origin, pathname } = window.location;
  return `${origin}${pathname}#share=${encoded}`;
}

export function decodeShareFromHash(hash: string): SharedReport | null {
  const match = /(?:^#|&)share=([^&]+)/.exec(hash);
  if (!match) return null;
  try {
    const json = fromBase64Url(match[1]);
    const parsed = JSON.parse(json);
    if (!parsed || typeof parsed.caseId !== "string" || !parsed.scanResult) return null;
    return parsed as SharedReport;
  } catch {
    return null; // malformed/tampered link — treat as "no shared report", never throw
  }
}
