# Day 19: Threat Behaviour Model & Graph Attack Path Forecasting

## 1. Attack Progression State Machine
By observing the active MITRE Tactic associated with an asset, the Digital Twin forecasts probable downstream attack paths:

[ TA0043: Reconnaissance ]
│ (Active Scanning: T1595)
▼
[ TA0001: Initial Access ] ──► Targets Exposed D002 (Web Server)
│ (Exploit Public App: T1190)
▼
[ TA0002: Execution ]      ──► Drops D002 into COMPROMISED State
│ (Command Shell: T1059.004)
▼
[ TA0007: Discovery ]      ──► Enumerates Corporate-LAN Subnet
│ (Network Service Discovery: T1046)
▼
[ TA0008: Lateral Movement ]──► Attempts Pivot to D003 (Finance PC) or D004 (Router)
│ (Remote Services: T1021)
▼
[ TA0010: Exfiltration ]   ──► Egress over Port 443 out to WAN


## 2. Value for Digital Twin Simulation
- Rather than detecting attacks retrospectively, the graph evaluates node vulnerability and connectivity to predict:
  $$\text{Next Target Node} = \arg\max_{v \in \text{Neighbors}(u)} \left( \text{Criticality}(v) \times \text{Exposure}(u, v) \right)$$