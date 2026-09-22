import React from "react";
import { ShieldCheck, AlertTriangle, AlertCircle, Flame, HelpCircle } from "lucide-react";
import { Confidence, RiskBand } from "../lib/types";

interface ThreatGaugeProps {
  score: number;
  bandInfo: RiskBand;
  confidence: Confidence;
}

export const ThreatGauge: React.FC<ThreatGaugeProps> = ({
  score,
  bandInfo,
  confidence,
}) => {
  const radius = 64;
  const strokeWidth = 12;
  const circumference = 2 * Math.PI * radius;
  const clampedScore = Math.max(0, Math.min(100, score));
  const offset = circumference - (clampedScore / 100) * circumference;

  const bandColor = `var(${bandInfo.colorVar})`;
  const bandBg = `var(${bandInfo.bgVar})`;

  const renderIcon = () => {
    switch (bandInfo.key) {
      case "safe":
        return <ShieldCheck size={16} />;
      case "warn":
        return <AlertTriangle size={16} />;
      case "danger":
        return <AlertCircle size={16} />;
      case "crit":
        return <Flame size={16} />;
    }
  };

  return (
    <div className="threat-overview-grid">
      <div className="gauge-container">
        <svg className="gauge-svg" viewBox="0 0 170 170">
          <circle
            className="gauge-track"
            cx="85"
            cy="85"
            r={radius}
            strokeWidth={strokeWidth}
          />
          <circle
            className="gauge-progress"
            cx="85"
            cy="85"
            r={radius}
            strokeWidth={strokeWidth}
            stroke={bandColor}
            strokeDasharray={circumference}
            strokeDashoffset={offset}
          />
        </svg>

        <div className="gauge-center-content">
          <span className="gauge-value tabular" style={{ color: bandColor }}>
            {score}
          </span>
          <span className="gauge-max">/ 100 INDEX</span>
        </div>
      </div>

      <div className="verdict-info-card">
        <div className="verdict-badges-row">
          <div
            className="risk-pill"
            style={{
              color: bandColor,
              backgroundColor: bandBg,
              borderColor: bandColor,
            }}
          >
            {renderIcon()}
            <span>THREAT LEVEL: {bandInfo.label.toUpperCase()}</span>
          </div>

          <div
            className="confidence-pill"
            title={confidence.note}
          >
            <span>CONFIDENCE: <strong>{confidence.label.toUpperCase()}</strong></span>
            <HelpCircle size={12} style={{ opacity: 0.7 }} />
          </div>
        </div>

        <p style={{ fontSize: "13px", color: "var(--text-dim)" }}>
          {bandInfo.key === "crit" && "Severe indicators detected. Immediate risk of credential compromise or financial fraud."}
          {bandInfo.key === "danger" && "High likelihood of advance-fee fraud, credential theft, or phishing deception."}
          {bandInfo.key === "warn" && "Moderate suspicion: multiple pressure cues or atypical contact methods detected."}
          {bandInfo.key === "safe" && "Low threat score. No standard scam markers or phishing heuristics triggered."}
        </p>
      </div>
    </div>
  );
};
