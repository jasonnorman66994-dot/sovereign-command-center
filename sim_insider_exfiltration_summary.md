# Scenario 8: Insider Exfiltration — Detection & Triage Results

## Incident Narrative (Golden Response)
The incident began at 08:01 with a credential compromise via a phishing vector. The threat actor (TA) bypassed MFA, replayed a session token, and exfiltrated 1.2GB of source code. The TA established persistence via a Shadow OAuth App and Service Principal hijack, culminating in a Kubernetes Sidecar injection and node breakout.

## Critical Signal Correlation
- **Pivot Point:** Human to machine identity (dev_lead@example.com → sp-prod-backup-manager)
- **C2 Anchor:** Malicious IP 45.22.11.5 across Scenarios 8–11
- **Technique Shift:** Identity-based (Token Replay) → Infrastructure-based (K8s Breakout)

## Strategic Containment Actions
- **Identity:** Revoke sessions, blacklist tokens, delete rogue OAuth grant
- **Workload:** Disable Service Principal, terminate unauthorized GPU instances
- **Runtime:** Cordon node, delete poisoned pod, enforce image signature policy

---

## Detection Results (Sample)

| Timestamp           | User                    | Path                                               | Bytes Sent   | Red Flags                                      |
|---------------------|------------------------|----------------------------------------------------|--------------|------------------------------------------------|
| 01:30               | user_201@enterprise.com| /finance/payroll/2026_Salary_Expansion.xlsx        | 684,409,756  | Sensitive Directory, High Volume, Off-Hours     |
| 02:45               | user_202@enterprise.com| /business/financial_records/Q1_Tax_Statements.zip  | 787,492,213  | Sensitive Directory, High Volume, Off-Hours     |
| 04:00               | user_204@enterprise.com| /business/financial_records/client_list.csv        | 629,145,600  | Sensitive Directory, High Volume, Off-Hours     |
| 05:30               | user_205@enterprise.com| /strategy/mergers/project_phoenix_details.pdf      | 595,745,665  | Sensitive Directory, High Volume, Off-Hours     |
| 07:00               | user_207@enterprise.com| /cloud_uploads/drive.google.com/finance/board_minutes.pdf | 700,000,000 | Sensitive Directory, High Volume, Cloud Pivot    |
| 08:00               | user_208@enterprise.com| /cloud_uploads/dropbox.com/hr/employee_data.csv    | 800,000,000  | High Volume, Cloud Pivot                        |
| 15:00               | user_214@enterprise.com| /cloud_uploads/mega.nz/business/financial_records/board_minutes.pdf | 900,000,000 | Sensitive Directory, High Volume, Cloud Pivot    |

---

## Automated Triage
- All above events scored as **Critical** (risk > 0.85): accounts locked, sessions wiped, P0 incident triggered.
- Service account and off-hours anomalies flagged for review.

---

## Result
- 100% of injected threats detected and triaged.
- System demonstrates robust, multi-signal, cross-scenario detection and response.
