import React from "react";
import { NavigationRouteId } from "../../types/dashboard";

interface KpiCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  badgeText?: string;
  badgeVariant?: "default" | "destructive" | "warning" | "success";
  details?: { label: string; count: number }[];
  targetRoute: NavigationRouteId;
  onDrillDown: (route: NavigationRouteId) => void;
}

export const KpiCard: React.FC<KpiCardProps> = ({
  title,
  value,
  subtitle,
  badgeText,
  badgeVariant = "default",
  details,
  targetRoute,
  onDrillDown
}) => {
  const badgeColors = {
    default: "bg-muted text-muted-foreground border-border",
    destructive: "bg-destructive/15 text-destructive border-destructive/30",
    warning: "bg-amber-500/15 text-amber-500 border-amber-500/30",
    success: "bg-emerald-500/15 text-emerald-500 border-emerald-500/30"
  };

  return (
    <div
      onClick={() => onDrillDown(targetRoute)}
      className="p-4 rounded-lg border border-border bg-card hover:border-primary/50 transition-all cursor-pointer shadow-sm hover:shadow-md flex flex-col justify-between"
    >
      <div>
        <div className="flex items-center justify-between">
          <span className="text-xs uppercase font-mono tracking-wider text-muted-foreground">{title}</span>
          {badgeText && (
            <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${badgeColors[badgeVariant]}`}>
              {badgeText}
            </span>
          )}
        </div>
        <div className="mt-2 text-2xl font-bold tracking-tight text-foreground">{value}</div>
        {subtitle && <p className="text-xs text-muted-foreground mt-0.5">{subtitle}</p>}
      </div>

      {details && details.length > 0 && (
        <div className="mt-3 pt-3 border-t border-border grid grid-cols-2 gap-1 text-[11px] font-mono text-muted-foreground">
          {details.map((d, i) => (
            <div key={i} className="flex justify-between pr-2">
              <span>{d.label}:</span>
              <strong className="text-foreground">{d.count}</strong>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};