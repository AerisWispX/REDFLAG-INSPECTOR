import { apiLimiter, reportConfirmLimiter } from "../src/lib/rateLimit";

function runTests() {
  console.log("=== RATE LIMITER TESTS ===\n");
  let passed = true;

  // Use unique keys per test so this file can run independently of whatever
  // else may have already consumed these shared limiter instances.
  const key1 = "test-key-" + Date.now();

  // 1. apiLimiter allows exactly its configured limit (10/min), then blocks.
  let allowedCount = 0;
  for (let i = 0; i < 12; i++) {
    if (apiLimiter.tryConsume(key1)) allowedCount++;
  }
  console.log(`1. apiLimiter allowed ${allowedCount}/12 rapid calls (limit is 10)`);
  if (allowedCount !== 10) {
    console.error(`  FAIL: expected exactly 10 allowed, got ${allowedCount}`);
    passed = false;
  } else {
    console.log("  PASS: exactly 10 allowed, the rest blocked");
  }

  // 2. The 11th/12th call already consumed above must report a real,
  // positive retry-after time now that the limiter is saturated.
  const retryMs = apiLimiter.retryAfterMs(key1);
  console.log(`2. retryAfterMs when saturated: ${retryMs}ms`);
  if (!(retryMs > 0)) {
    console.error("  FAIL: expected a positive retry-after time once the limit is hit");
    passed = false;
  } else {
    console.log("  PASS: positive retry-after time reported");
  }

  // 3. A different key is an independent bucket — must not be affected by
  // key1's saturation above.
  const key2 = "test-key-independent-" + Date.now();
  const key2Allowed = apiLimiter.tryConsume(key2);
  console.log(`3. A fresh, unrelated key (key2) allowed: ${key2Allowed}`);
  if (!key2Allowed) {
    console.error("  FAIL: a different key should not be limited by another key's usage");
    passed = false;
  } else {
    console.log("  PASS: keys are independent buckets");
  }

  // 4. reportConfirmLimiter (20/min) is a distinct instance/config from
  // apiLimiter (10/min) — same key, different limiter, should allow more.
  const key3 = "test-key-confirm-" + Date.now();
  let confirmAllowed = 0;
  for (let i = 0; i < 25; i++) {
    if (reportConfirmLimiter.tryConsume(key3)) confirmAllowed++;
  }
  console.log(`4. reportConfirmLimiter allowed ${confirmAllowed}/25 (limit is 20)`);
  if (confirmAllowed !== 20) {
    console.error(`  FAIL: expected exactly 20 allowed, got ${confirmAllowed}`);
    passed = false;
  } else {
    console.log("  PASS: reportConfirmLimiter's own 20/min limit enforced independently of apiLimiter");
  }

  if (!passed) process.exit(1);
  console.log("\nALL RATE LIMITER TESTS PASSED.");
}

runTests();
