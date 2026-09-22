import React from "react";
import { Sparkles, ShieldAlert, HelpCircle } from "lucide-react";
import { AiAnalysis } from "../lib/types";

interface AiAnalysisPanelProps {
  isLoading: boolean;
  analysis?: AiAnalysis;
  hasScanned: boolean;
}

const VERDICT_LABEL: Record<AiAnalysis["verdict"], string> = {
  scam: "Reads as a scam",
  suspicious: "Reads as suspicious",
  legitimate: "Reads as legitimate",
  uncertain: "Uncertain",
};

export const AiAnalysisPanel: React.FC<AiAnalysisPanelProps> = ({ isLoading, analysis, hasScanned }) => {
  return (
    <section className="case-card ai-panel">
      <div className="section-label">
        07 — AI Analysis
        <span className="ai-badge">
          <Sparkles size={11} />
          Model opinion, not a verified fact
        </span>
      </div>

      {isLoading ? (
        <div className="loading-row">
          <div className="spinner" />
          <span>Reading the message for scam indicators (Groq · openai/gpt-oss-120b)…</span>
        </div>
      ) : !analysis ? (
        <div className="empty-state">
          {hasScanned
            ? "Not available — no GROQ_KEY configured on this server."
            : "Run a scan to see the model's read of this message."}
        </div>
      ) : analysis.rateLimited ? (
        <span className="inline-alert dim" title="Groq free tier">
          <HelpCircle size={14} />
          <span>Rate limited — try again shortly.</span>
        </span>
      ) : analysis.error ? (
        <span className="inline-alert dim">
          <HelpCircle size={14} />
          <span>Unavailable ({analysis.error}). The score above already reflects local heuristics only.</span>
        </span>
      ) : (
        <>
          <div className="ai-verdict-row">
            <span className={`ai-verdict-pill ${analysis.verdict}`}>{VERDICT_LABEL[analysis.verdict]}</span>
            <span className="ai-confidence">confidence: {analysis.confidence}</span>
          </div>

          <p className="ai-reasoning">{analysis.reasoning || "No reasoning returned."}</p>

          {analysis.promptInjectionAttempt && (
            <div className="ai-injection-warning">
              <ShieldAlert size={15} />
              <span>This message contains text attempting to instruct the AI classifier itself — a red flag on its own, and not obeyed.</span>
            </div>
          )}

          <div className="ai-meta-row">
            <span>Language: {analysis.languageDetected}</span>
            <span>
              Score influence: {analysis.scoreAdjustment >= 0 ? "+" : ""}
              {analysis.scoreAdjustment} (capped ±15, cannot force Severe on its own)
            </span>
            <span>Model: {analysis.model}</span>
          </div>
        </>
      )}
    </section>
  );
};
