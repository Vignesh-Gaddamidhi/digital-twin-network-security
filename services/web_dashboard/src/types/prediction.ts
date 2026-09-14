export type EarlyWarningStateEnum =
  | "NO_WARNING"
  | "WATCH"
  | "EARLY_WARNING"
  | "HIGH_CONFIDENCE_WARNING"
  | "IMPACT_STAGE";

export type PredictedAttackCategoryEnum =
  | "NORMAL"
  | "PORT_SCAN"
  | "BRUTE_FORCE_LIKE"
  | "DOS_LIKE"
  | "DNS_ANOMALY"
  | "BEACONING"
  | "LATERAL_MOVEMENT_LIKE"
  | "EXFILTRATION_LIKE";

export interface ShapFeatureContribution {
  featureName: string;
  featureLabel: string;
  shapValue: number; // e.g. +0.31
  formattedValue: string; // e.g. "+0.31"
  normalizedMagnitude: number; // 0.0 to 1.0 for bar width
  direction: "POSITIVE" | "NEGATIVE";
}

export interface ModelMetadata {
  modelType: string;       // "GRU" or "RandomForest"
  modelVersion: string;    // "v1.2"
  featureVersion: string;  // "v1.0"
  predictionHorizon: string; // "+60s"
  timestamp: string;
}

export interface PredictionXaiPayload {
  predictionId: string;
  deviceId: string;
  currentThreatProbability: number;
  currentThreatFormatted: string;
  futureThreatProbability: number;
  futureThreatFormatted: string;
  earlyWarningState: EarlyWarningStateEnum;
  earlyWarningMessage: string;
  predictedCategory: PredictedAttackCategoryEnum;
  categoryConfidence: number;
  categoryConfidenceFormatted: string;
  riskScore: number;
  riskLevel: string;
  model: ModelMetadata;
  topFeatures: ShapFeatureContribution[];
  naturalLanguageExplanation: string;
  explanationChain: string[];
  disclaimer: string;
  timestamp: string;
}