# Unified MITRE ATT&CK Heatmap (Across All Scenarios)

## Legend

- High ([HIGH]) - Appears in 5+ scenarios
- Medium ([MED]) - Appears in 3-4 scenarios
- Low ([LOW]) - Appears in 1-2 scenarios
- None ([NONE]) - Not observed

## ATT&CK Heatmap

| MITRE Tactic | Technique | ID | Frequency | Heat |
|---|---|---|---|---|
| Collection | Email Collection | T1114 | Scenario 10, Scenario 13 | [LOW] Low |
| Collection | Data Staging | T1074 | Scenario 15 | [LOW] Low |
| Credential Access | Credential Dumping | T1003 | Scenario 15, Scenario 16 | [LOW] Low |
| Credential Access | Brute Force | T1110 | Scenario 11 | [LOW] Low |
| Defense Evasion | Indicator Removal | T1070 | Scenario 10, Scenario 11, Scenario 13 | [MED] Medium |
| Defense Evasion | Obfuscated/Encrypted Payloads | T1027 | Scenario 12 | [LOW] Low |
| Discovery | Account Discovery | T1087 | Scenario 10, Scenario 15 | [LOW] Low |
| Discovery | Cloud Service Discovery | T1526 | Scenario 16 | [LOW] Low |
| Execution | PowerShell Execution | T1059.001 | Scenario 11, Scenario 15 | [LOW] Low |
| Execution | User Execution | T1204 | Scenario 10, Scenario 13 | [LOW] Low |
| Exfiltration | Exfiltration Over Web Services | T1567 | Scenario 10, Scenario 13, Scenario 15 | [MED] Medium |
| Exfiltration | Exfiltration to Cloud Storage | T1537 | Scenario 16 | [LOW] Low |
| Impact | Inhibit System Recovery | T1490 | Scenario 10, Scenario 13 | [LOW] Low |
| Impact | Data Encryption for Impact | T1486 | Scenario 10 | [LOW] Low |
| Initial Access | Phishing / Spam Burst | T1566 | Scenario 10, Scenario 11, Scenario 13 | [MED] Medium |
| Initial Access | Valid Accounts | T1078 | Scenario 16 | [LOW] Low |
| Initial Access | Supply Chain Compromise | T1195 | Scenario 12 | [LOW] Low |
| Lateral Movement | Remote Services | T1021 | Scenario 15, Scenario 16 | [LOW] Low |
| Lateral Movement | Pass-the-Token | T1134.002 | Scenario 11 | [LOW] Low |
| Persistence | Mailbox Rule Modification | T1114.003 | Scenario 10, Scenario 13 | [LOW] Low |
| Persistence | Account Manipulation | T1098 | Scenario 16 | [LOW] Low |
| Privilege Escalation | Abuse Elevation Control Mechanisms | T1548 | Scenario 10, Scenario 13, Scenario 16 | [MED] Medium |
| Privilege Escalation | Exploitation for Privilege Escalation | T1068 | Scenario 13 | [LOW] Low |

## Heatmap Summary

- High techniques: 0
- Medium techniques: 4
- Low techniques: 19
- None techniques: 0

### Most Recurrent Behavior Cluster

Top recurrence in this dataset is 3 scenario(s) per technique (below the 5+ High threshold).

- Indicator Removal (T1070) in Scenario 10, Scenario 11, Scenario 13 [[MED] Medium]
- Exfiltration Over Web Services (T1567) in Scenario 10, Scenario 13, Scenario 15 [[MED] Medium]
- Phishing / Spam Burst (T1566) in Scenario 10, Scenario 11, Scenario 13 [[MED] Medium]
- Abuse Elevation Control Mechanisms (T1548) in Scenario 10, Scenario 13, Scenario 16 [[MED] Medium]

## Interpretation

1. The recurring pattern centers on initial access, escalation, evasion, and exfiltration.
2. Under-represented areas include cloud discovery, lateral movement depth, and broader impact patterns.
3. Detection priorities should focus on privilege escalation, mailbox rule changes, exfiltration, and anti-evasion controls.
