// Community reports — persistent storage, no database dependency.
//
// A plain JSON file (data/reports.json) rather than SQLite/Postgres: this
// app's other rate limiters already document the "in-process only" caveat
// for anything that needs sharing across requests, and this is the first
// feature where that's genuinely not good enough — a scam report has to
// survive a restart and be visible to every visitor, not just the browser
// that submitted it. A JSON file gets that durability with zero new
// dependencies (no npm install, no external DB to provision — appropriate
// for this project's scale) and stays human-inspectable for a hackathon
// demo. It would NOT be the right choice at real-world scale or under
// concurrent writes from multiple server processes — see the note at the
// bottom of this file.
//
// Concurrency: within a single Node process, all writes are serialized
// through `writeQueue` below, so two nearly-simultaneous requests (e.g. two
// people confirming the same report at once) can't race and silently drop
// one write — each write waits for the previous one to finish, read the
// freshly-written file, then apply its own change.

import fs from "node:fs/promises";
import path from "node:path";
import { ScamReport, ScamReportInput } from "../src/lib/types";

const DATA_DIR = path.join(process.cwd(), "data");
const DATA_FILE = path.join(DATA_DIR, "reports.json");

async function ensureStore(): Promise<void> {
  await fs.mkdir(DATA_DIR, { recursive: true });
  try {
    await fs.access(DATA_FILE);
  } catch {
    await fs.writeFile(DATA_FILE, "[]", "utf-8");
  }
}

async function readAll(): Promise<ScamReport[]> {
  await ensureStore();
  try {
    const raw = await fs.readFile(DATA_FILE, "utf-8");
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return []; // corrupt/missing file reads as empty rather than crashing the endpoint
  }
}

async function writeAll(reports: ScamReport[]): Promise<void> {
  await ensureStore();
  // Write to a temp file then rename — rename is atomic on the same
  // filesystem, so a reader never sees a half-written file even if the
  // process is killed mid-write.
  const tmp = `${DATA_FILE}.${process.pid}.${Date.now()}.tmp`;
  await fs.writeFile(tmp, JSON.stringify(reports, null, 2), "utf-8");
  await fs.rename(tmp, DATA_FILE);
}

// Serializes every write through this process against this file — see the
// concurrency note above.
let writeQueue: Promise<unknown> = Promise.resolve();
function withWriteLock<T>(fn: () => Promise<T>): Promise<T> {
  const result = writeQueue.then(fn, fn);
  writeQueue = result.catch(() => undefined);
  return result;
}

function makeId(): string {
  return `rpt_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
}

const MAX_STORED_REPORTS = 500; // hackathon-scale cap; oldest pending/removed pruned first, verified reports kept longest

export async function listReports(opts: { includeRemoved?: boolean } = {}): Promise<ScamReport[]> {
  const all = await readAll();
  const visible = opts.includeRemoved ? all : all.filter((r) => r.status !== "removed");
  return visible.sort((a, b) => {
    // Verified first, then by confirm count, then newest.
    if (a.status !== b.status) return a.status === "verified" ? -1 : b.status === "verified" ? 1 : 0;
    if (b.confirmCount !== a.confirmCount) return b.confirmCount - a.confirmCount;
    return new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime();
  });
}

export async function createReport(input: ScamReportInput): Promise<ScamReport> {
  return withWriteLock(async () => {
    const all = await readAll();
    const report: ScamReport = {
      id: makeId(),
      createdAt: new Date().toISOString(),
      category: input.category,
      domain: input.domain,
      urlOrEmail: input.urlOrEmail,
      textPreview: input.textPreview.slice(0, 400),
      score: input.score,
      bandLabel: input.bandLabel,
      note: input.note.slice(0, 500),
      confirmCount: 0,
      status: "pending",
    };
    all.push(report);
    // Prune oldest non-verified reports first if over the cap, so the file
    // (and the public feed) can't grow unbounded from spam.
    const trimmed =
      all.length > MAX_STORED_REPORTS
        ? [...all]
            .sort((a, b) => {
              if (a.status !== b.status) return a.status === "verified" ? 1 : b.status === "verified" ? -1 : 0;
              return new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime();
            })
            .slice(all.length - MAX_STORED_REPORTS)
        : all;
    await writeAll(trimmed);
    return report;
  });
}

export async function confirmReport(id: string): Promise<ScamReport | null> {
  return withWriteLock(async () => {
    const all = await readAll();
    const report = all.find((r) => r.id === id);
    if (!report) return null;
    report.confirmCount += 1;
    await writeAll(all);
    return report;
  });
}

export async function moderateReport(id: string, action: "verify" | "remove" | "unverify"): Promise<ScamReport | null> {
  return withWriteLock(async () => {
    const all = await readAll();
    const report = all.find((r) => r.id === id);
    if (!report) return null;
    if (action === "verify") report.status = "verified";
    else if (action === "remove") report.status = "removed";
    else if (action === "unverify") report.status = "pending";
    await writeAll(all);
    return report;
  });
}

// --- Production note, not implemented here (deliberately out of scope for
// this pass) ---
// A JSON file has no row-level locking and doesn't survive multiple server
// processes/instances sharing the same reports (each would have its own
// file, or need a shared filesystem + still race on concurrent writes
// across processes — the in-process writeQueue above only protects against
// races *within* one process). If this app is ever deployed with more than
// one server instance, or needs report volume beyond a few thousand
// entries, replace this file with a real database (SQLite with a proper
// client for single-instance durability, or Postgres/MySQL for multi-instance).
