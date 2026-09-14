import React from "react";
import { NavigationRouteId, NavigationItem } from "../../types/dashboard";

interface SidebarNavProps {
  items: NavigationItem[];
  currentRoute: NavigationRouteId;
  isOpen: boolean;
  onSelectRoute: (id: NavigationRouteId) => void;
}

export const SidebarNav: React.FC<SidebarNavProps> = ({ items, currentRoute, isOpen, onSelectRoute }) => {
  return (
    <aside
      className={`fixed md:static inset-y-0 left-0 z-20 transition-all duration-300 ease-in-out border-r border-border bg-card flex flex-col ${
        isOpen ? "w-64" : "w-0 md:w-16 overflow-hidden"
      }`}
    >
      <div className="h-16 flex items-center px-4 border-b border-border">
        <div className="flex items-center gap-2 font-bold text-foreground tracking-wider">
          <span className="p-1.5 rounded bg-primary text-primary-foreground text-xs font-mono">DT</span>
          {isOpen && <span className="text-sm uppercase tracking-wide">Command Center</span>}
        </div>
      </div>

      <nav className="flex-1 py-4 px-2 space-y-1 overflow-y-auto">
        {items.map((item) => {
          const isActive = currentRoute === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onSelectRoute(item.id)}
              className={`w-full flex items-center justify-between px-3 py-2.5 rounded-md text-xs font-medium transition-colors ${
                isActive
                  ? "bg-primary text-primary-foreground"
                  : "text-muted-foreground hover:bg-accent hover:text-accent-foreground"
              }`}
            >
              <div className="flex items-center gap-3 truncate">
                <span className="w-5 text-center font-mono">#</span>
                {isOpen && <span className="truncate">{item.label}</span>}
              </div>
              {isOpen && item.badgeCount && (
                <span
                  className={`text-[10px] px-1.5 py-0.5 rounded-full font-mono ${
                    item.badgeVariant === "destructive"
                      ? "bg-destructive/20 text-destructive border border-destructive/30"
                      : "bg-amber-500/20 text-amber-500 border border-amber-500/30"
                  }`}
                >
                  {item.badgeCount}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      <div className="p-3 border-t border-border text-[11px] text-muted-foreground">
        {isOpen ? <span>Engine v3.0 | Week 21</span> : <span className="text-center block">v3</span>}
      </div>
    </aside>
  );
};