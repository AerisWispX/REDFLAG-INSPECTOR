import { checkTyposquat, checkTyposquatBatch } from "../src/lib/typosquat";

function runTests() {
  console.log("=== TYPOSQUAT DETECTION TESTS ===\n");
  let passed = true;

  // 1. Exact match to a known brand must NOT be flagged — it's the real domain.
  const exact = checkTyposquat("linkedin.com");
  console.log("1. Exact match (linkedin.com):", exact);
  if (exact !== null) {
    console.error("  FAIL: exact match to a known brand should return null");
    passed = false;
  } else {
    console.log("  PASS: exact match correctly not flagged");
  }

  // 2. One-character substitution should be flagged at distance 1.
  const oneChar = checkTyposquat("linkedln.com");
  console.log("2. One-char lookalike (linkedln.com):", oneChar);
  if (!oneChar || oneChar.brand !== "linkedin.com" || oneChar.distance !== 1) {
    console.error("  FAIL: expected a distance-1 match against linkedin.com");
    passed = false;
  } else {
    console.log("  PASS: correctly flagged at distance 1");
  }

  // 3. An unrelated, short, real-world domain should not false-positive
  // just because it happens to be a similar length to some brand.
  const unrelated = checkTyposquat("example.org");
  console.log("3. Unrelated domain (example.org):", unrelated);
  if (unrelated !== null) {
    console.error("  FAIL: an unrelated domain should not be flagged as a typosquat");
    passed = false;
  } else {
    console.log("  PASS: unrelated domain correctly not flagged");
  }

  // 4. www. prefix should be normalized away before comparing.
  const withWww = checkTyposquat("www.linkedin.com");
  console.log("4. www.-prefixed exact match:", withWww);
  if (withWww !== null) {
    console.error("  FAIL: www.linkedin.com should normalize to the real domain and not be flagged");
    passed = false;
  } else {
    console.log("  PASS: www. prefix normalized correctly");
  }

  // 5. Batch dedupes and only returns real matches.
  const batch = checkTyposquatBatch(["linkedin.com", "linkedln.com", "linkedln.com", "example.org"]);
  console.log("5. Batch result count:", batch.length, batch);
  if (batch.length !== 1) {
    console.error("  FAIL: expected exactly 1 flagged (deduped) domain from the batch, got", batch.length);
    passed = false;
  } else {
    console.log("  PASS: batch correctly deduped and returned exactly 1 flagged domain");
  }

  if (!passed) process.exit(1);
  console.log("\nALL TYPOSQUAT TESTS PASSED.");
}

runTests();
