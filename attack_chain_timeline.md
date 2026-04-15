# 11-Scenario Attack Chain Timeline

| Time  | Scenario | Key Event | User/Identity | Detection | Response |
|-------|----------|-----------|---------------|-----------|----------|
| 08:01 | 8        | Phishing, credential compromise | dev_lead@example.com | Detected | Session revoked, alert triggered |
| 08:10 | 8        | Impossible Travel, token replay | dev_lead@example.com | Detected | Token blacklisted |
| 08:15 | 8        | Source code exfiltration (1.2GB) | dev_lead@example.com | Detected | Account locked |
| 08:20 | 9        | Shadow OAuth App authorized | dev_lead@example.com | Detected | OAuth grant deleted |
| 08:30 | 10       | Service Principal hijack | sp-prod-backup-manager | Detected | Service Principal disabled |
| 08:45 | 11       | K8s Sidecar injection | sp-prod-backup-manager | Detected | Pod deleted, node cordoned |
| 09:00 | 11       | Node breakout, root access | sp-prod-backup-manager | Detected | Image signature policy enforced |
