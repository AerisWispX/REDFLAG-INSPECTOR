// Typosquat / lookalike-domain detection.
//
// Scam job and rental listings frequently impersonate a real, trusted brand
// with a domain that's one or two characters off (linkedln-jobs.com,
// zi11ow.com, indeedcareers.net). This runs entirely offline — no API call,
// no network — as a local heuristic, exactly like the regex rules, and is
// wired into scanText() via extracted email/URL domains rather than a
// regex over raw text (a domain isn't a fixed string to match against).

const KNOWN_BRANDS = [
  // job boards / hiring platforms
  "linkedin.com",
  "indeed.com",
  "glassdoor.com",
  "ziprecruiter.com",
  "monster.com",
  "careerbuilder.com",
  "simplyhired.com",
  "dice.com",
  "angel.co",
  "wellfound.com",
  // rental / real-estate platforms
  "zillow.com",
  "apartments.com",
  "trulia.com",
  "rent.com",
  "craigslist.org",
  "airbnb.com",
  "hotpads.com",
  "realtor.com",
  "redfin.com",
  // large employers commonly impersonated in fake-offer scams
  "google.com",
  "microsoft.com",
  "amazon.com",
  "meta.com",
  "apple.com",
  "adobe.com",
  "salesforce.com",
  "oracle.com",
  "ibm.com",
  "accenture.com",
  "deloitte.com",
  "infosys.com",
  "tcs.com",
  "wipro.com",
  "cognizant.com",
  "capgemini.com",
];

function levenshtein(a: string, b: string): number {
  const dp: number[][] = Array.from({ length: a.length + 1 }, () => new Array(b.length + 1).fill(0));
  for (let i = 0; i <= a.length; i++) dp[i][0] = i;
  for (let j = 0; j <= b.length; j++) dp[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      dp[i][j] =
        a[i - 1] === b[j - 1] ? dp[i - 1][j - 1] : 1 + Math.min(dp[i - 1][j - 1], dp[i - 1][j], dp[i][j - 1]);
    }
  }
  return dp[a.length][b.length];
}

export interface TyposquatMatch {
  domain: string;
  brand: string;
  distance: number;
}

/**
 * Returns the closest known brand this domain resembles, if it's an exact
 * match (legitimate, not flagged) or too different (unrelated, not flagged)
 * — only domains 1-2 edits away from a known brand are reported, since that
 * band is where typosquatting lives and false positives from unrelated
 * short domains become common past distance 2.
 */
export function checkTyposquat(rawDomain: string): TyposquatMatch | null {
  const domain = rawDomain.toLowerCase().replace(/^www\./, "").trim();
  if (!domain || KNOWN_BRANDS.includes(domain)) return null;

  let best: TyposquatMatch | null = null;
  for (const brand of KNOWN_BRANDS) {
    if (Math.abs(brand.length - domain.length) > 3) continue; // cheap prefilter
    const distance = levenshtein(domain, brand);
    if (distance >= 1 && distance <= 2) {
      if (!best || distance < best.distance) best = { domain, brand, distance };
    }
  }
  return best;
}

/** Convenience: run checkTyposquat across every unique domain found in a set of emails/urls. */
export function checkTyposquatBatch(domains: string[]): TyposquatMatch[] {
  const seen = new Set<string>();
  const matches: TyposquatMatch[] = [];
  for (const d of domains) {
    const norm = d.toLowerCase().replace(/^www\./, "");
    if (seen.has(norm)) continue;
    seen.add(norm);
    const m = checkTyposquat(norm);
    if (m) matches.push(m);
  }
  return matches;
}
