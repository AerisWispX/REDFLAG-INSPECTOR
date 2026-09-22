// Tests the real persistence layer against the real data/reports.json —
// deliberately, since the whole point of this store is disk durability
// (see reportsStore.ts's header comment). To avoid leaving test data behind
// in a file the running app also reads, the original file content is
// snapshotted before these tests run and restored in a `finally`, whether
// the tests pass or fail.

import fs from "node:fs/promises";
import path from "node:path";
import { createReport, confirmReport, moderateReport, listReports } from "../api/reportsStore";

const DATA_FILE = path.join(process.cwd(), "data", "reports.json");

async function snapshotDataFile(): Promise<string | null> {
  try {
    return await fs.readFile(DATA_FILE, "utf-8");
  } catch {
    return null; // file doesn't exist yet — restore step will just remove it again
  }
}

async function restoreDataFile(original: string | null) {
  if (original === null) {
    await fs.rm(DATA_FILE, { force: true });
  } else {
    await fs.writeFile(DATA_FILE, original, "utf-8");
  }
}

async function runTests() {
  console.log("=== REPORTS STORE (PERSISTENCE) TESTS ===\n");
  let passed = true;
  const original = await snapshotDataFile();

  try {
    // 1. Create a report and confirm it round-trips through disk with the
    // fields we expect, truncated where the store promises to truncate.
    const created = await createReport({
      category: "job_offer",
      domain: "test-domain.example",
      urlOrEmail: "hr@test-domain.example",
      textPreview: "x".repeat(500), // longer than the 400-char cap
      score: 82,
      bandLabel: "Severe",
      note: "y".repeat(600), // longer than the 500-char cap
    });
    console.log("1. Created report:", created.id, "textPreview length:", created.textPreview.length, "note length:", created.note.length);
    if (created.textPreview.length !== 400 || created.note.length !== 500) {
      console.error("  FAIL: expected textPreview capped at 400 chars and note capped at 500 chars");
      passed = false;
    } else if (created.status !== "pending" || created.confirmCount !== 0) {
      console.error("  FAIL: a new report should start pending with 0 confirms");
      passed = false;
    } else {
      console.log("  PASS: created report has correctly truncated fields and starts pending/0 confirms");
    }

    // 2. It should now appear in the public listing.
    const afterCreate = await listReports();
    const found = afterCreate.find((r) => r.id === created.id);
    console.log("2. Found in public listing after create:", !!found);
    if (!found) {
      console.error("  FAIL: newly created report should appear in listReports()");
      passed = false;
    } else {
      console.log("  PASS: appears in the public listing");
    }

    // 3. Confirming increments the count and persists.
    const confirmed = await confirmReport(created.id);
    console.log("3. confirmCount after one confirm:", confirmed?.confirmCount);
    if (confirmed?.confirmCount !== 1) {
      console.error("  FAIL: expected confirmCount to be 1 after a single confirm");
      passed = false;
    } else {
      console.log("  PASS: confirm count incremented correctly");
    }

    // 4. Moderating to "removed" should drop it from the default public
    // listing but keep it visible with includeRemoved: true.
    await moderateReport(created.id, "remove");
    const publicAfterRemove = await listReports();
    const adminAfterRemove = await listReports({ includeRemoved: true });
    const stillPublic = publicAfterRemove.some((r) => r.id === created.id);
    const stillInAdmin = adminAfterRemove.some((r) => r.id === created.id);
    console.log(`4. After remove — visible publicly: ${stillPublic}, visible to admin: ${stillInAdmin}`);
    if (stillPublic || !stillInAdmin) {
      console.error("  FAIL: a removed report must disappear from the public feed but remain visible to admin listings");
      passed = false;
    } else {
      console.log("  PASS: removed report correctly hidden from public feed, still visible to admin");
    }

    // 5. Confirming/moderating a nonexistent id returns null, not a throw.
    const missingConfirm = await confirmReport("rpt_does_not_exist");
    const missingModerate = await moderateReport("rpt_does_not_exist", "verify");
    console.log("5. Nonexistent id — confirm:", missingConfirm, "moderate:", missingModerate);
    if (missingConfirm !== null || missingModerate !== null) {
      console.error("  FAIL: operating on a nonexistent report id should return null, not throw or fabricate a result");
      passed = false;
    } else {
      console.log("  PASS: nonexistent id handled gracefully");
    }
  } finally {
    await restoreDataFile(original);
    console.log("\n(data/reports.json restored to its pre-test state)");
  }

  if (!passed) process.exit(1);
  console.log("\nALL REPORTS STORE TESTS PASSED.");
}

runTests();
