// Community reporting endpoints — the public feed and its moderation.
//
// Three operations, three different trust levels:
//  - listReports: public, read-only, no auth.
//  - submitReport / confirmReport: public write, but rate-limited per IP
//    (src/lib/rateLimit.ts) since they write into something every visitor
//    sees — the cost of abuse here is a spammed public feed, not just a
//    drained API quota.
//  - moderateReport: requires ADMIN_KEY. This is a single shared secret,
//    not a user-account system — see the header comment in
//    src/components/AdminPanel.tsx for why that's the deliberate scope for
//    this pass, and what a real multi-admin deployment would need instead.

import { ScamReport, ScamReportInput } from "../src/lib/types";
import { listReports, createReport, confirmReport, moderateReport } from "./reportsStore";
import { reportSubmitLimiter, reportConfirmLimiter } from "../src/lib/rateLimit";

const ALLOWED_CATEGORIES = new Set(["job_offer", "rental_listing", "other"]);

function isValidReportInput(body: any): body is ScamReportInput {
  return (
    body &&
    typeof body === "object" &&
    ALLOWED_CATEGORIES.has(body.category) &&
    (body.domain === null || typeof body.domain === "string") &&
    (body.urlOrEmail === null || typeof body.urlOrEmail === "string") &&
    typeof body.textPreview === "string" &&
    typeof body.score === "number" &&
    body.score >= 0 &&
    body.score <= 100 &&
    typeof body.bandLabel === "string" &&
    typeof body.note === "string"
  );
}

export async function handleListReports(): Promise<ScamReport[]> {
  return listReports();
}

export async function handleSubmitReport(
  body: unknown,
  ip: string
): Promise<{ report?: ScamReport; error?: string; rateLimited?: boolean }> {
  if (!reportSubmitLimiter.tryConsume(ip)) {
    return { rateLimited: true };
  }
  if (!isValidReportInput(body)) {
    return { error: "invalid_input" };
  }
  const report = await createReport(body);
  return { report };
}

export async function handleConfirmReport(
  id: string,
  ip: string
): Promise<{ report?: ScamReport; error?: string; rateLimited?: boolean }> {
  if (!reportConfirmLimiter.tryConsume(ip)) {
    return { rateLimited: true };
  }
  if (!id || typeof id !== "string") return { error: "invalid_id" };
  const report = await confirmReport(id);
  if (!report) return { error: "not_found" };
  return { report };
}

function isAdminAuthorized(providedKey: string | undefined): boolean {
  const adminKey = process.env.ADMIN_KEY;
  // If no ADMIN_KEY is configured on the server, moderation is disabled
  // entirely rather than defaulting open — an unset secret must never mean
  // "anyone is admin".
  if (!adminKey) return false;
  return typeof providedKey === "string" && providedKey.length > 0 && providedKey === adminKey;
}

export async function handleModerateReport(
  id: string,
  action: string,
  providedKey: string | undefined
): Promise<{ report?: ScamReport; error?: string }> {
  if (!isAdminAuthorized(providedKey)) {
    return { error: "unauthorized" };
  }
  if (action !== "verify" && action !== "remove" && action !== "unverify") {
    return { error: "invalid_action" };
  }
  if (!id || typeof id !== "string") return { error: "invalid_id" };
  const report = await moderateReport(id, action);
  if (!report) return { error: "not_found" };
  return { report };
}

// Separate from the public listing: includes removed reports and doesn't
// pre-sort verified-first, so the admin queue reads newest-first regardless
// of status — the thing an admin needs to triage first is the newest
// pending report, not whatever already has the most confirms.
export async function handleAdminList(providedKey: string | undefined): Promise<{ reports?: ScamReport[]; error?: string }> {
  if (!isAdminAuthorized(providedKey)) {
    return { error: "unauthorized" };
  }
  const all = await listReports({ includeRemoved: true });
  return { reports: [...all].sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()) };
}
