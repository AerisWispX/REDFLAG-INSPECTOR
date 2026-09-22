import React from "react";
import { ScoreBreakdownLine } from "../lib/types";

interface ScoreBreakdownProps {
  score: number;
  breakdown: ScoreBreakdownLine[];
  isFloorActive: boolean;
}

export const ScoreBreakdown: React.FC<ScoreBreakdownProps> = ({
  score,
  breakdown,
  isFloorActive,
}) => {
  const generateExplanation = (): string => {
    if (score === 0 || breakdown.length === 0) {
      return "Why this score: No suspicious red flags or heuristic triggers were identified in the submitted material.";
    }

    const topCategories = breakdown.slice(0, 2).map((b) => `${b.name} (+${b.contribution} pts)`);

    if (isFloorActive) {
      return `Why this score: The overall index was elevated by the high-risk floor override (minimum 55 pts) because severe single-category patterns were identified in ${breakdown[0]?.name || "critical sectors"}.`;
    }

    if (topCategories.length === 1) {
      return `Why this score: Score is primarily driven by ${topCategories[0]}.`;
    }

    return `Why this score: Score is primarily driven by ${topCategories.join(" and ")}, spanning ${breakdown.length} independent warning categories.`;
  };

  return (
    <div className="score-breakdown-section">
      <div className="breakdown-chips-row">
        {breakdown.map((item, idx) => (
          <span key={idx} className="contrib-chip">
            +{item.contribution} {item.name}
          </span>
        ))}
      </div>

      <p className="why-score-line">{generateExplanation()}</p>
    </div>
  );
};
