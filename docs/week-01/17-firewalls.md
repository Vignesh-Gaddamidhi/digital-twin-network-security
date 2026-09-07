# Day 6: Stateful Firewalls & Packet Filtering Engines

## 1. Stateful Filtering Model
- Tracks connection state sequences (`NEW`, `ESTABLISHED`, `RELATED`, `INVALID`).
- Unsolicited inbound traffic is dropped by default unless explicit rules permit it.
- Outbound requests allow automatic two-way communication for returning sessions.

## 2. Rule Evaluation Sequence
Rules evaluate top-down sequentially:
1. **First-Match Execution:** If a packet matches Rule 1, its action (`ALLOW` / `DROP`) is applied immediately.
2. **Implicit Deny:** Any packet failing all listed rules hits the final implicit `DROP` policy.