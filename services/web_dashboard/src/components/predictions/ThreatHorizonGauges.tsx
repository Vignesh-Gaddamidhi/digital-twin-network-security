import React from "react";
import { EarlyWarningStateEnum, PredictedAttackCategoryEnum } from "../../types/prediction";

interface ThreatHorizonGaugesProps {
  currentThreat: number;
  currentThreatFormatted: string;
  futureThreat: number;
  futureThreatFormatted: string;
  earlyWarningState: EarlyWarningStateEnum;
  earlyWarningMessage: string;
  predictedCategory: PredictedAttackCategoryEnum;
  categoryConfidenceFormatted: string;
  riskLevel: string;
}

export const ThreatHorizonGauges: React.FC<ThreatHorizonGaugesProps> = ({
  currentThreat,
  currentThreatFormatted,
  futureThreat,
  futureThreatFormatted,
  earlyWarningState,
  earlyWarningMessage,
  predictedCategory,
  categoryConfidenceFormatted,
  riskLevel
}) => {
  const warningBadgeColors: Record<EarlyWarningStateEnum, string> = {
    NO_WARNING: "bg-emerald-500/15 text-emerald-500 border-emerald-500/30",
    WATCH: "bg-amber-500/15 text-amber-500 border-amber-500/30",
    EARLY_WARNING: "bg-orange-500/15 text-orange-500 border-orange-500/30 animate-pulse",
    HIGH_CONFIDENCE_WARNING: "bg-destructive/15 text-destructive border-destructive/30 animate-pulse",
    IMPACT_STAGE: "bg-destructive/25 text-destructive border-destructive/50 animate-bounce"
  };

  return (
    <div className="p-4 rounded-lg border border-border bg-card">
      <div className="flex items-center justify-between border-b border-border pb-3 mb-4">
        <div>
          <span className="text-[11px] uppercase font-mono tracking-wider text-muted-foreground">Threat Intelligence</span>
          <h3 className="text-base font-bold font-mono text-foreground flex items-center gap-2">
            {predictedCategory}
            <span className="text-xs font-normal text-muted-foreground">({categoryConfidenceFormatted} Confidence)</span>
          </h3>
        </div>
        <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${warningBadgeColors[earlyWarningState]}`}>
          {earlyWarningState}
        </span>
      </div>

      <div className="grid grid-cols-2 gap-4">
        {/* Current Threat Probability */}
        <div className="p-3 rounded border border-border bg-muted/20">
          <div className="flex justify-between items-center text-xs font-mono mb-1">
            <span className="text-muted-foreground">Current Threat</span>
            <strong className="text-foreground">{currentThreatFormatted}</strong>
          </div>
          <div className="w-full h-2 rounded-full bg-muted overflow-hidden">
            <div
              className="h-full bg-sky-500 rounded-full transition-all duration-500"
              style={{ width: `${currentThreat * 100}%` }}
            />
          </div>
          <span className="text-[10px] text-muted-foreground block mt-1">Instantaneous classification</span>
        </div>

        {/* Future Threat Probability (Phase 14 Time-Series) */}
        <div className="p-3 rounded border border-border bg-muted/20">
          <div className="flex justify-between items-center text-xs font-mono mb-1">
            <span className="text-muted-foreground">Future Threat (+60s)</span>
            <strong className="text-orange-500">{futureThreatFormatted}</strong>
          </div>
          <div className="w-full h-2 rounded-full bg-muted overflow-hidden">
            <div
              className="h-full bg-orange-500 rounded-full transition-all duration-500"
              style={{ width: `${futureThreat * 100}%` }}
            />
          </div>
          <span className="text-[10px] text-muted-foreground block mt-1">Recurrent GRU forecast horizon</span>
        </div>
      </div>

      <p className="text-xs font-mono text-muted-foreground mt-3 bg-muted/30 p-2 rounded border border-border/50">
        💡 {earlyWarningMessage}
      </p>
    </div>
  );
};