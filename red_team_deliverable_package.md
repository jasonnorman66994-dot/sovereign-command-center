# Red Team Deliverable Package — 2026-04-14

This package defines campaign operating modes and formal red-team deliverables for Mission Control exercises.

## Campaign Modes

### One Scenario at a Time

- Mode: `one-scenario-at-a-time`
- Description: Run one scenario at a time for focused detection and response drills.
- Currently available scenarios: 17

### Multi-Scenario Chains

- Description: Run pre-defined chained campaigns for correlation and escalation analysis.
- Numeric shorthand example: 3 -> 5 -> 9 -> 14
- Example chain: SCENARIO_3_UNAUTHORIZED_ACCESS -> SCENARIO_5_OAUTH_ABUSE -> SCENARIO_9_LATERAL_MOVEMENT_OAUTH -> SCENARIO_14_HYBRID_CLOUD_RANSOMWARE
- Recommended chains:
  - SCENARIO_3_UNAUTHORIZED_ACCESS -> SCENARIO_5_OAUTH_ABUSE -> SCENARIO_9_LATERAL_MOVEMENT_OAUTH -> SCENARIO_14_HYBRID_CLOUD_RANSOMWARE
  - SCENARIO_5_OAUTH_ABUSE -> SCENARIO_10_SERVICE_PRINCIPAL_HIJACK -> SCENARIO_12_SUPPLY_CHAIN_POISONING -> SCENARIO_16_OIDC_SIGNING_KEY_THEFT
  - SCENARIO_11_K8S_SIDECAR_BREAKOUT -> SCENARIO_13_ZERO_DAY_EXPLOIT -> SCENARIO_17_HARDWARE_ROOT_OF_TRUST_COMPROMISE

### Full-Spectrum Campaign

- Description: Run Scenario 1 through Scenario 20 in sequence as a simulated, synthetic, safe campaign.
- Numeric shorthand sequence: Scenario 1 -> 20 (simulated, synthetic, safe)
- Sequence policy: Scenario 1 -> Scenario 20 (simulated, synthetic, safe)
- Current sequence status:
  - 01. SCENARIO_1_SPAM_BURST [available]
  - 02. SCENARIO_2_MALWARE_ATTACHMENT [available]
  - 03. SCENARIO_3_UNAUTHORIZED_ACCESS [available]
  - 04. SCENARIO_4_BEC_ATTEMPT [available]
  - 05. SCENARIO_5_OAUTH_ABUSE [available]
  - 06. SCENARIO_6_VENDOR_COMPROMISE [available]
  - 07. SCENARIO_7_INSIDER_MISUSE [available]
  - 08. SCENARIO_8_TOKEN_REPLAY_IMPOSSIBLE_TRAVEL [available]
  - 09. SCENARIO_9_LATERAL_MOVEMENT_OAUTH [available]
  - 10. SCENARIO_10_SERVICE_PRINCIPAL_HIJACK [available]
  - 11. SCENARIO_11_K8S_SIDECAR_BREAKOUT [available]
  - 12. SCENARIO_12_SUPPLY_CHAIN_POISONING [available]
  - 13. SCENARIO_13_ZERO_DAY_EXPLOIT [available]
  - 14. SCENARIO_14_HYBRID_CLOUD_RANSOMWARE [available]
  - 15. SCENARIO_15_CROSS_TENANT_FEDERATION_ABUSE [available]
  - 16. SCENARIO_16_OIDC_SIGNING_KEY_THEFT [available]
  - 17. SCENARIO_17_HARDWARE_ROOT_OF_TRUST_COMPROMISE [available]
  - 18. SCENARIO_18_SYNTHETIC_PLACEHOLDER [synthetic_placeholder]
  - 19. SCENARIO_19_SYNTHETIC_PLACEHOLDER [synthetic_placeholder]
  - 20. SCENARIO_20_SYNTHETIC_PLACEHOLDER [synthetic_placeholder]

## 8) Red Team Deliverable Package

- Package name: Red Team Deliverable Package
- Deliverables:
  - Campaign scope and objectives
  - Scenario inject matrix
  - Unified incident attack graph
  - Detection and response checkpoints
  - Executive communication brief
  - Blue-team scoring workbook
  - After-action review template
  - Safety, legal, and control constraints

## Safety Controls

- No live malware deployment
- No unauthorized external network targeting
- No destructive commands against production systems
- Synthetic payloads and controlled telemetry only

