import React from "react";
import { AlertOctagon, XCircle } from "lucide-react";
import { RiskBandKey } from "../lib/types";

interface DoNotCalloutProps {
  items: string[];
  bandKey: RiskBandKey;
}

export const DoNotCallout: React.FC<DoNotCalloutProps> = ({ items, bandKey }) => {
  // Only display for High ("danger") or Severe ("crit")
  if (bandKey !== "danger" && bandKey !== "crit") {
    return null;
  }

  if (!items || items.length === 0) {
    return null;
  }

  return (
    <div className="do-not-box" role="alert">
      <div className="do-not-header">
        <AlertOctagon size={16} />
        <span>CRITICAL DIRECTIVE — IMMEDIATE PROTECTIVE ACTIONS</span>
      </div>

      <ul className="do-not-list">
        {items.map((action, idx) => (
          <li key={idx} className="do-not-item">
            <XCircle size={15} className="do-not-icon" />
            <span>{action}</span>
          </li>
        ))}
      </ul>
    </div>
  );
};
