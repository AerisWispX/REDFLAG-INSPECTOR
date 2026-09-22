export function extractEmails(text: string): string[] {
  if (!text) return [];
  const regex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
  const matches = text.match(regex) || [];
  const normalized = matches.map((e) => e.toLowerCase().trim());
  return Array.from(new Set(normalized));
}

export function extractUrls(text: string): string[] {
  if (!text) return [];
  const regex = /https?:\/\/[^\s)]+/g;
  const matches = text.match(regex) || [];
  const cleaned = matches.map((url) => {
    // Strip trailing punctuation often adjacent to URLs in prose (e.g. .,;:)
    return url.replace(/[.,;:!?]+$/, "").trim();
  });
  return Array.from(new Set(cleaned)).filter((u) => u.length > 0);
}
