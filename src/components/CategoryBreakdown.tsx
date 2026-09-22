import React, { useState } from "react";
import { ChevronDown, CheckCircle2 } from "lucide-react";
import { CategoryResult } from "../lib/types";

interface CategoryBreakdownProps {
  categories: CategoryResult[];
}

export const CategoryBreakdown: React.FC<CategoryBreakdownProps> = ({ categories }) => {
  // Start with categories that have hits open by default for clear forensic review
  const [expandedIds, setExpandedIds] = useState<Record<string, boolean>>(() => {
    const initial: Record<string, boolean> = {};
    categories.forEach((cat) => {
      if (cat.hits.length > 0) {
        initial[cat.id] = true;
      }
    });
    return initial;
  });

  const toggleCategory = (id: string) => {
    setExpandedIds((prev) => ({
      ...prev,
      [id]: !prev[id],
    }));
  };

  const getStripeColor = (cat: CategoryResult) => {
    if (cat.hits.length === 0) return "var(--line)";
    const raw = cat.hits.reduce((acc, h) => acc + h.points, 0);
    if (raw >= 70) return "var(--danger)";
    if (raw >= 35) return "var(--warn)";
    return "var(--accent)";
  };

  return (
    <section className="case-card">
      <div className="section-label">03 — Signal & Heuristic Breakdown</div>

      <div className="categories-list">
        {categories.map((cat) => {
          const isExpanded = !!expandedIds[cat.id];
          const hasHits = cat.hits.length > 0;
          const stripeColor = getStripeColor(cat);

          return (
            <div key={cat.id} className="category-row">
              <button
                type="button"
                className="category-header-btn"
                onClick={() => toggleCategory(cat.id)}
                aria-expanded={isExpanded}
                aria-controls={`category-panel-${cat.id}`}
              >
                <div className="category-header-left">
                  <span
                    className="severity-stripe"
                    style={{ backgroundColor: stripeColor }}
                  />
                  <div className="category-titles">
                    <div className="category-name-row">
                      <span className="category-name">{cat.name}</span>
                      <span style={{ fontSize: "11px", color: "var(--text-dim)", fontFamily: "var(--font-mono)" }}>
                        (Weight {cat.weight}%)
                      </span>
                    </div>
                    <span className="category-desc">{cat.description}</span>
                  </div>
                </div>

                <div className="category-header-right">
                  <span className={`hit-count-badge ${hasHits ? "has-hits" : ""}`}>
                    {cat.hits.length} {cat.hits.length === 1 ? "signal" : "signals"}
                  </span>
                  <ChevronDown
                    size={16}
                    className={`accordion-chevron ${isExpanded ? "expanded" : ""}`}
                  />
                </div>
              </button>

              {isExpanded && (
                <div className="category-expanded-content" id={`category-panel-${cat.id}`} role="region" aria-label={`${cat.name} signals`}>
                  {cat.hits.length === 0 ? (
                    <div style={{ fontSize: "13px", color: "var(--text-dim)", fontStyle: "italic", display: "flex", alignItems: "center", gap: "6px" }}>
                      <CheckCircle2 size={14} style={{ color: "var(--safe)" }} />
                      <span>No suspicious indicators detected in this category.</span>
                    </div>
                  ) : (
                    cat.hits.map((hit, idx) => {
                      const isStrong = hit.points >= 35;
                      const isLive = hit.source === "live";

                      return (
                        <div key={idx} className="hit-card">
                          <div className="hit-card-header">
                            <span className="hit-title">{hit.title}</span>
                            <div className="hit-tags-group">
                              {isLive ? (
                                <span className="signal-tag live-badge">VERIFIED LIVE</span>
                              ) : isStrong ? (
                                <span className="signal-tag strong">STRONG SIGNAL (+{hit.points})</span>
                              ) : (
                                <span className="signal-tag supporting">SUPPORTING SIGNAL (+{hit.points})</span>
                              )}
                            </div>
                          </div>

                          <p className="hit-explanation">{hit.explanation}</p>

                          {hit.evidence && (
                            <div className="hit-evidence-box">
                              <span style={{ color: "var(--text-dim)", fontSize: "10px", display: "block", marginBottom: "2px" }}>
                                EXTRACTED EVIDENCE:
                              </span>
                              <code>"{hit.evidence}"</code>
                            </div>
                          )}
                        </div>
                      );
                    })
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </section>
  );
};
