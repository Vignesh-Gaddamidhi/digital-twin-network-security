import React from "react";
import { ShapFeatureContribution } from "../../types/prediction";

interface ShapContributionBarsProps {
  features: ShapFeatureContribution[];
}

export const ShapContributionBars: React.FC<ShapContributionBarsProps> = ({ features }) => {
  return (
    <div className="p-4 rounded-lg border border-border bg-card">
      <div className="flex items-center justify-between mb-3">
        <h4 className="text-xs uppercase font-mono font-semibold text-foreground tracking-wider">
          Why Was This Predicted? (Local SHAP Values)
        </h4>
        <span className="text-[10px] font-mono text-muted-foreground">Phase 15 Attribution</span>
      </div>

      <div className="space-y-3">
        {features.map((f) => (
          <div key={f.featureName} className="text-xs font-mono">
            <div className="flex justify-between text-muted-foreground mb-1">
              <span className="text-foreground">{f.featureLabel}</span>
              <strong className={f.shapValue >= 0 ? "text-orange-500" : "text-emerald-500"}>
                {f.formattedValue}
              </strong>
            </div>
            <div className="w-full h-2.5 rounded-full bg-muted overflow-hidden">
              <div
                className={`h-full rounded-full transition-all duration-500 ${
                  f.shapValue >= 0 ? "bg-orange-500" : "bg-emerald-500"
                }`}
                style={{ width: `${Math.min(100, f.normalizedMagnitude * 100)}%` }}
              />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};