import React from "react";
import { ModelMetadata } from "../../types/prediction";

interface ExplanationChainCardProps {
  explanation: string;
  chain: string[];
  model: ModelMetadata;
  disclaimer: string;
}

export const ExplanationChainCard: React.FC<ExplanationChainCardProps> = ({
  explanation,
  chain,
  model,
  disclaimer
}) => {
  return (
    <div className="p-4 rounded-lg border border-border bg-card space-y-3">
      <div>
        <h4 className="text-xs uppercase font-mono font-semibold text-foreground tracking-wider mb-1">
          Synthesized Natural-Language Evidence
        </h4>
        <p className="text-xs text-foreground leading-relaxed bg-muted/20 p-2.5 rounded border border-border font-mono">
          {explanation}
        </p>
      </div>

      <div>
        <span className="text-[11px] uppercase font-mono text-muted-foreground block mb-1">
          Reasoning Provenance Chain:
        </span>
        <div className="flex flex-wrap items-center gap-1.5 text-[11px] font-mono">
          {chain.map((step, idx) => (
            <React.Fragment key={idx}>
              <span className="px-2 py-0.5 rounded bg-muted text-foreground border border-border">
                {step}
              </span>
              {idx < chain.length - 1 && <span className="text-muted-foreground">→</span>}
            </React.Fragment>
          ))}
        </div>
      </div>

      <div className="flex items-center justify-between text-[10px] font-mono text-muted-foreground pt-2 border-t border-border">
        <span>Model: {model.modelType} ({model.modelVersion}) | Horizon: {model.predictionHorizon}</span>
        <span>Features: {model.featureVersion}</span>
      </div>

      <p className="text-[10px] text-muted-foreground italic border-t border-border/40 pt-2">
        ℹ {disclaimer}
      </p>
    </div>
  );
};