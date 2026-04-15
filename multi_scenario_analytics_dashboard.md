# Multi-Scenario Analytics Dashboard

## Detection Coverage
| Scenario | Total Events | Threats Detected | Detection Rate |
|----------|-------------|------------------|---------------|
| 8        | 24          | 12               | 50%           |
| 9        | 10          | 6                | 60%           |
| 10       | 8           | 6                | 75%           |
| 11       | 6           | 5                | 83%           |

## Cross-Scenario User/IP Correlation
| User/Identity           | Scenarios Involved |
|------------------------|--------------------|
| dev_lead@example.com   | 8, 9               |
| sp-prod-backup-manager | 10, 11             |
| attacker_ip_45.22.11.5 | 8, 9, 10, 11       |

## Detection Gaps
- Scenario 8: 2 low-volume exfil events not flagged
- Scenario 9: 2 OAuth refresh token grants missed
- Scenario 10: 1 VM manipulation event not detected
- Scenario 11: All critical events detected

## Dwell Time (min)
| Scenario | Min | Max |
|----------|-----|-----|
| 8        | 2   | 14  |
| 9        | 1   | 10  |
| 10       | 3   | 12  |
| 11       | 2   | 8   |
