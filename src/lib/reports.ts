import { ScamReport, ScamReportInput } from "./types";

export async function fetchReports(): Promise<ScamReport[]> {
  const res = await fetch("/api/reports");
  if (!res.ok) return [];
  const data = await res.json();
  return data.reports || [];
}

export async function submitReport(
  input: ScamReportInput
): Promise<{ report?: ScamReport; error?: string }> {
  const res = await fetch("/api/reports", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(input),
  });
  if (res.status === 429) return { error: "rate_limited" };
  if (!res.ok) return { error: "failed" };
  const data = await res.json();
  return { report: data.report };
}

export async function confirmReport(id: string): Promise<{ report?: ScamReport; error?: string }> {
  const res = await fetch(`/api/reports/${encodeURIComponent(id)}/confirm`, { method: "POST" });
  if (res.status === 429) return { error: "rate_limited" };
  if (!res.ok) return { error: "failed" };
  const data = await res.json();
  return { report: data.report };
}

export async function fetchAdminReports(adminKey: string): Promise<{ reports?: ScamReport[]; error?: string }> {
  const res = await fetch("/api/admin/reports", { headers: { "x-admin-key": adminKey } });
  if (res.status === 401) return { error: "unauthorized" };
  if (!res.ok) return { error: "failed" };
  const data = await res.json();
  return { reports: data.reports || [] };
}

export async function moderateReportAction(
  id: string,
  action: "verify" | "remove" | "unverify",
  adminKey: string
): Promise<{ report?: ScamReport; error?: string }> {
  const res = await fetch(`/api/reports/${encodeURIComponent(id)}/moderate`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "x-admin-key": adminKey },
    body: JSON.stringify({ action }),
  });
  if (res.status === 401) return { error: "unauthorized" };
  if (!res.ok) return { error: "failed" };
  const data = await res.json();
  return { report: data.report };
}
