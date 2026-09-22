import React, { KeyboardEvent, useMemo } from "react";
import { Search, CornerDownLeft, Trash2, FileText, Sparkles, Building2, KeyRound, CheckCircle2 } from "lucide-react";

export const SAMPLES = {
  scam: `Dear Candidate, Congratulations! You have been shortlisted for the position of Data Entry Executive (Work From Home) with a starting salary of $4,500/month. No experience required. To confirm your appointment and process your joining kit, you are required to pay a fully refundable registration fee of $150 within 24 hours. Slots are limited and this offer expires today.
Please make the payment via Google Pay or a gift card to secure your seat, and share the receipt on WhatsApp at +1-202-555-0199. Once confirmed, you will also need to purchase your equipment (laptop + software license) through our approved vendor before your start date. Regards, HR Team,
globalhire.jobs@gmail.com`,

  rental: `Hi, Thanks for your interest in the 2-bed apartment downtown ($950/month, all utilities included). I’m currently out of the country for work so I can’t show it in person, but here are the photos attached. To hold the unit before someone else takes it, please wire a refundable security deposit of $500 plus first month’s rent via Western Union or Zelle to my property manager today. Once I receive payment confirmation I’ll overnight the keys and signed lease. Thanks, The Landlord`,

  credential: `Hi, welcome aboard! Final step before your first day: please verify your identity by replying with your Social Security Number, a scanned copy of your driver’s license, and your bank account login so we can set up your direct deposit ahead of your start date. You can also confirm everything faster — just click here to verify:
http://hr-verify-portal.com/login. Thanks, Payroll Team`,

  legitimate: `Dear Priya Nair, We are pleased to offer you the position of Software Engineer II at Meridian Systems Inc., reporting to Alex Torres, Engineering Manager. Your starting date is proposed for 14 October, with an annual base salary of $92,000. This offer is contingent on a standard background check, coordinated by hr@meridiansystems.com — there is no cost to you at any stage. Call our office at (415) 555-0142 with questions, or reply by 30 September to accept. Warm regards, Jordan Blake, HR Business Partner, Meridian Systems Inc.`,
};

interface InputConsoleProps {
  text: string;
  onChangeText: (val: string) => void;
  onScan: () => void;
  isScanning: boolean;
}

export const InputConsole: React.FC<InputConsoleProps> = ({
  text,
  onChangeText,
  onScan,
  isScanning,
}) => {
  const isMac = typeof window !== "undefined" && /Mac|iPod|iPhone|iPad/.test(navigator.platform);

  const stats = useMemo(() => {
    const trimmed = text.trim();
    const charCount = text.length;
    const wordCount = trimmed ? trimmed.split(/\s+/).length : 0;
    return { charCount, wordCount };
  }, [text]);

  const handleKeyDown = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
      e.preventDefault();
      onScan();
    }
  };

  return (
    <section className="case-card input-console-card">
      <div className="section-header-row">
        <div className="section-label" style={{ marginBottom: 0 }}>
          <FileText size={13} style={{ color: "var(--accent)" }} />
          <span>01 — Submit Material for Inspection</span>
        </div>
        <div className="input-stats-badge mono">
          <span>{stats.wordCount} words</span>
          <span>•</span>
          <span>{stats.charCount} chars</span>
        </div>
      </div>

      <div className="textarea-wrapper">
        <textarea
          className="input-textarea"
          placeholder="Paste the full offer letter, recruiter email, WhatsApp message, or rental listing text here…"
          value={text}
          onChange={(e) => onChangeText(e.target.value)}
          onKeyDown={handleKeyDown}
          rows={6}
          aria-label="Text to inspect for scam patterns"
        />
        {text && (
          <button
            type="button"
            className="textarea-floating-clear"
            onClick={() => onChangeText("")}
            title="Clear text"
            aria-label="Clear input text"
          >
            <Trash2 size={13} />
          </button>
        )}
      </div>

      <div className="input-controls-row">
        <div className="sample-chips-container">
          <span className="chips-label mono">Load benchmark sample:</span>
          <div className="sample-chips-group">
            <button
              type="button"
              className="chip-btn"
              onClick={() => onChangeText(SAMPLES.scam)}
            >
              <Sparkles size={11} className="chip-icon text-accent" />
              <span>Job Scam</span>
            </button>
            <button
              type="button"
              className="chip-btn"
              onClick={() => onChangeText(SAMPLES.rental)}
            >
              <Building2 size={11} className="chip-icon text-warn" />
              <span>Rental Trap</span>
            </button>
            <button
              type="button"
              className="chip-btn"
              onClick={() => onChangeText(SAMPLES.credential)}
            >
              <KeyRound size={11} className="chip-icon text-danger" />
              <span>Credential Phish</span>
            </button>
            <button
              type="button"
              className="chip-btn"
              onClick={() => onChangeText(SAMPLES.legitimate)}
            >
              <CheckCircle2 size={11} className="chip-icon text-safe" />
              <span>Legitimate Offer</span>
            </button>
            <button
              type="button"
              className="chip-btn clear-chip"
              onClick={() => onChangeText("")}
            >
              <Trash2 size={11} />
              <span>Clear</span>
            </button>
          </div>
        </div>

        <div className="action-buttons-group">
          <span className="shortcut-hint mono">
            {isMac ? "⌘+Enter" : "Ctrl+Enter"}
          </span>
          <button
            type="button"
            className="scan-submit-btn"
            onClick={onScan}
            disabled={isScanning || !text.trim()}
          >
            <Search size={15} />
            <span>{isScanning ? "Scanning…" : "Run Threat Scan"}</span>
            <CornerDownLeft size={13} className="btn-corner-icon" />
          </button>
        </div>
      </div>
    </section>
  );
};
