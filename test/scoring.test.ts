import { scanText, band } from "../src/lib/scoring";

// Typosquat sample: fires ONLY the impersonation check (a lookalike of
// linkedin.com, one character off) — nothing else in the message should
// match any other category, so this isolates the new offline domain-
// similarity check added alongside VirusTotal.
const TYPOSQUAT_SAMPLE = `Please apply through our careers portal at hr@linkedln.com for further steps.`;

// Spanish sample: a scam message using no English scam vocabulary at all,
// to verify the Spanish rule set (p7/p8/u3/h4/h5/i4/i5) actually fires
// rather than the message silently scoring near-zero for being non-English.
const SPANISH_SAMPLE = `Estimado candidato, para confirmar su puesto debe pagar una cuota de registro mediante tarjeta de regalo. Cupos limitados, responda de inmediato.`;

const SCAM_JOB_SAMPLE = `Dear Candidate, Congratulations! You have been shortlisted for the position of Data Entry Executive (Work From Home) with a starting salary of $4,500/month. No experience required. To confirm your appointment and process your joining kit, you are required to pay a fully refundable registration fee of $150 within 24 hours. Slots are limited and this offer expires today.
Please make the payment via Google Pay or a gift card to secure your seat, and share the receipt on WhatsApp at +1-202-555-0199. Once confirmed, you will also need to purchase your equipment (laptop + software license) through our approved vendor before your start date. Regards, HR Team,
globalhire.jobs@gmail.com`;

const RENTAL_TRAP_SAMPLE = `Hi, Thanks for your interest in the 2-bed apartment downtown ($950/month, all utilities included). I’m currently out of the country for work so I can’t show it in person, but here are the photos attached. To hold the unit before someone else takes it, please wire a refundable security deposit of $500 plus first month’s rent via Western Union or Zelle to my property manager today. Once I receive payment confirmation I’ll overnight the keys and signed lease. Thanks, The Landlord`;

const CREDENTIAL_PHISHING_SAMPLE = `Hi, welcome aboard! Final step before your first day: please verify your identity by replying with your Social Security Number, a scanned copy of your driver’s license, and your bank account login so we can set up your direct deposit ahead of your start date. You can also confirm everything faster — just click here to verify:
http://hr-verify-portal.com/login. Thanks, Payroll Team`;

const LEGITIMATE_SAMPLE = `Dear Priya Nair, We are pleased to offer you the position of Software Engineer II at Meridian Systems Inc., reporting to Alex Torres, Engineering Manager. Your starting date is proposed for 14 October, with an annual base salary of $92,000. This offer is contingent on a standard background check, coordinated by hr@meridiansystems.com — there is no cost to you at any stage. Call our office at (415) 555-0142 with questions, or reply by 30 September to accept. Warm regards, Jordan Blake, HR Business Partner, Meridian Systems Inc.`;

function runTests() {
  console.log("=== RUNNING SCORING ENGINE REGRESSION TESTS ===\n");
  let passed = true;

  // 1. Scam job sample
  const scamRes = scanText(SCAM_JOB_SAMPLE);
  const scamBand = band(scamRes.score);
  console.log(`1. Scam Sample: Score = ${scamRes.score} (Band: ${scamBand.label})`);
  // 59, not the original 63: adding the "impersonation" category (weight 8)
  // took weight from channel/identity/language/link to keep the total at
  // 100 — this sample doesn't trigger impersonation, so its score dropped
  // by exactly that redistribution. Re-verify with `npm test` after any
  // future weight change to CATEGORIES.
  if (scamRes.score !== 59 || scamBand.label !== "High") {
    console.error(`  FAIL: Expected 59 (High), got ${scamRes.score} (${scamBand.label})`);
    passed = false;
  } else {
    console.log("  PASS: Exactly 59 (High)");
  }

  // 2. Rental trap sample
  const rentalRes = scanText(RENTAL_TRAP_SAMPLE);
  const rentalBand = band(rentalRes.score);
  console.log(`2. Rental Trap Sample: Score = ${rentalRes.score} (Band: ${rentalBand.label})`);
  if (rentalRes.score !== 55 || rentalBand.label !== "High") {
    console.error(`  FAIL: Expected 55 (High via floor), got ${rentalRes.score} (${rentalBand.label})`);
    passed = false;
  } else {
    console.log("  PASS: Exactly 55 (High, floor override active)");
  }

  // 3. Credential phishing sample
  const credRes = scanText(CREDENTIAL_PHISHING_SAMPLE);
  const credBand = band(credRes.score);
  console.log(`3. Credential Phishing Sample: Score = ${credRes.score} (Band: ${credBand.label})`);
  if (credRes.score !== 55 || credBand.label !== "High") {
    console.error(`  FAIL: Expected 55 (High via floor), got ${credRes.score} (${credBand.label})`);
    passed = false;
  } else {
    console.log("  PASS: Exactly 55 (High, floor override active)");
  }

  // 4. Legitimate sample
  const legitRes = scanText(LEGITIMATE_SAMPLE);
  const legitBand = band(legitRes.score);
  console.log(`4. Legitimate Sample: Score = ${legitRes.score} (Band: ${legitBand.label})`);
  if (legitRes.score !== 0 || legitBand.label !== "Low") {
    console.error(`  FAIL: Expected 0 (Low), got ${legitRes.score} (${legitBand.label})`);
    passed = false;
  } else {
    console.log("  PASS: Exactly 0 (Low, zero false-positives)");
  }

  // 5. Typosquat / impersonation detection
  const typoRes = scanText(TYPOSQUAT_SAMPLE);
  const impersonationCat = typoRes.categories.find((c) => c.id === "impersonation");
  const flaggedLinkedin = impersonationCat?.hits.some((h) => h.evidence === "linkedln.com" && h.title.includes("linkedin.com"));
  console.log(`5. Typosquat Sample: impersonation hits = ${impersonationCat?.hits.length ?? 0}`);
  if (!flaggedLinkedin) {
    console.error(`  FAIL: Expected an impersonation hit flagging "linkedln.com" as a lookalike of "linkedin.com"`);
    passed = false;
  } else {
    console.log(`  PASS: "linkedln.com" correctly flagged as a 1-character lookalike of linkedin.com`);
  }

  // 6. Spanish-language rule coverage
  const esRes = scanText(SPANISH_SAMPLE);
  const spanishHitCount = esRes.categories.reduce(
    (n, c) => n + c.hits.filter((h) => h.title.includes("(Spanish)")).length,
    0
  );
  console.log(`6. Spanish Sample: score = ${esRes.score}, Spanish-tagged hits = ${spanishHitCount}`);
  if (spanishHitCount < 3) {
    console.error(`  FAIL: Expected at least 3 Spanish-tagged rules to fire (payment, urgency, identity), got ${spanishHitCount}`);
    passed = false;
  } else {
    console.log(`  PASS: ${spanishHitCount} Spanish-language rules fired across payment/urgency/identity`);
  }

  if (!passed) {
    process.exit(1);
  }
  console.log("\nALL 6 BENCHMARK TESTS PASSED PERFECTLY!");
}

runTests();
