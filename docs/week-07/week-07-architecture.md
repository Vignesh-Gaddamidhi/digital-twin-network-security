# Phase 6: Week 7 Architecture & Complete State Flow

                     REAL NETWORK
                          │
                          ▼
                   TELEMETRY DATA
                          │
                          ▼
                 ┌────────────────┐
                 │ DATA INGESTION │
                 └───────┬────────┘
                         │
                         ▼
                ┌──────────────────┐
                │ NORMALISATION    │
                └────────┬─────────┘
                         │
                         ▼
                  ┌──────────────┐
                  │ STATE ENGINE │
                  └───────┬──────┘
                          │
         ┌────────────────┼────────────────┐
         │                │                │
         ▼                ▼                ▼
     DEVICE           PERFORMANCE        NETWORK
      STATE              STATE            STATE
         │                │                │
         │           ┌────┼────┐           │
         │           │         │           │
         │          CPU      Memory     Connections
         │
         ├───────────────┐
         │               │
         ▼               ▼
       PORTS           SERVICES
         │               │
         └───────┬───────┘
                 │
                 ▼
           SECURITY STATE
                 │
          ┌──────┴──────┐
          ▼             ▼
      Security       Vulnerability
       Status           Status
          │             │
          └──────┬──────┘
                 │
                 ▼
             TWIN STATE
                 │
         ┌───────┴────────┐
         ▼                ▼
    Current State      State History
         ▲
         │
   ┌─────┴─────┐
   │ SIMULATION│
   │   EVENT   │
   └───────────┘