import React, { useState } from "react";
import { Flag, Check, AlertCircle } from "lucide-react";
import { ScanResult } from "../lib/types";
import { band } from "../lib/scoring";
import { submitReport } from "../lib/reports";

interface ReportButtonProps {
  scannedText: string;
  scanResult: ScanResult;
  forceSevere: boolean;
  extractedEmails: string[];
  extractedUrls: string[];
}

export const ReportButton: React.FC<ReportButtonProps> = ({
  scannedText,
  scanResult,
  forceSevere,
  extractedEmails,
  extractedUrls,
}) => {
  const [open, setOpen] = useState(false);
  const [category, setCategory] = useState<"job_offer" | "rental_listing" | "other">("job_offer");
  const [note, setNote] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [result, setResult] = useState<"success" | "rate_limited" | "error" | null>(null);

  const defaultTarget = extractedUrls[0] || extractedEmails[0] || null;
  const defaultDomain = extractedUrls[0]
    ? (() => {
        try {
          return new URL(extractedUrls[0]).hostname;
        } catch {
          return null;
        }
      })()
    : extractedEmails[0]?.split("@")[1] || null;

  const handleSubmit = async () => {
    setSubmitting(true);
    setResult(null);
    const { report, error } = await submitReport({
      category,
      domain: defaultDomain,
      urlOrEmail: defaultTarget,
      textPreview: scannedText.trim(),
      score: scanResult.score,
      bandLabel: band(scanResult.score, forceSevere).label,
      note: note.trim(),
    });
    setSubmitting(false);
    if (report) {
      setResult("success");
      setNote("");
      setTimeout(() => {
        setResult(null);
        setOpen(false);
      }, 2500);
    } else if (error === "rate_limited") {
      setResult("rate_limited");
    } else {
      setResult("error");
    }
  };

  if (!open) {
    return (
      <button type="button" className="copy-report-btn" onClick={() => setOpen(true)}>
        <Flag size={13} />
        <span>Report This Scam</span>
      </button>
    );
  }

  return (
    <div className="report-form">
      <div>
        <span className="form-field-label">Category</span>
        <select className="form-select" value={category} onChange={(e) => setCategory(e.target.value as any)}>
          <option value="job_offer">Job offer scam</option>
          <option value="rental_listing">Rental listing scam</option>
          <option value="other">Other</option>
        </select>
      </div>

      <div>
        <span className="form-field-label">Note for other visitors (optional)</span>
        <textarea
          className="form-textarea-sm"
          value={note}
          onChange={(e) => setNote(e.target.value.slice(0, 500))}
          placeholder="e.g. what tipped you off, or what happened when you engaged with them"
          aria-label="Optional note for other visitors"
        />
      </div>

      <p className="section-note">
        This submits a preview of the scanned text (first 400 characters), the computed score ({scanResult.score}/100),
        and the domain/contact found ({defaultTarget || "none detected"}) to a public feed anyone can see. It does not
        include your name or the full message.
      </p>

      {result === "success" && (
        <span className="copied-toast">
          <Check size={14} />
          <span>✓ Report submitted — thank you for helping others.</span>
        </span>
      )}
      {result === "rate_limited" && (
        <span className="inline-alert danger">
          <AlertCircle size={14} />
          <span>Too many reports from this connection — try again in a few minutes.</span>
        </span>
      )}
      {result === "error" && (
        <span className="inline-alert danger">
          <AlertCircle size={14} />
          <span>Could not submit — please try again.</span>
        </span>
      )}

      <div className="btn-row">
        <button type="button" className="report-submit-btn" onClick={handleSubmit} disabled={submitting}>
          {submitting ? "Submitting…" : "Submit Report"}
        </button>
        <button type="button" className="copy-report-btn" onClick={() => setOpen(false)}>
          Cancel
        </button>
      </div>
    </div>
  );
};
