# Incident Attack Graph — 2026-04-14

This artifact defines the unified attack-surface ontology for all Mission Control scenarios and links every scenario into a single graph-based incident model.

## Graph Summary

- Scenario coverage: 17
- Node count: 57
- Edge count: 78
- Terminal scenario: SCENARIO_17_HARDWARE_ROOT_OF_TRUST_COMPROMISE

## Node Types

- Scenario
- User
- Mailbox
- Session
- Identity Provider
- Federation Trust
- OAuth App
- Service Principal
- Device / Node
- Container / Pod
- VM / Workload
- Pipeline / Artifact
- Storage Bucket / Blob
- Network Endpoint
- TPM / Secure Enclave
- Hardware Attestation
- Attacker Infrastructure
- Event / Log Entry

## Relationship Types

- compromised_by
- issues_token_to
- assumes_role_in
- executes_on
- exfiltrates_to
- modifies
- creates_persistence_in
- moves_laterally_to
- forges_attestation_for
- extracts_key_from
- deploys_artifact_to
- encrypts
- spoofs_identity_of
- abused_by
- replayed_by
- signing_key_stolen_by
- targets
- observed_in
- validated_by

## Scenario-to-Graph Mapping

| Scenario | Layer | Risk | Primary Entities | Core Relationships |
|---|---|---|---|---|
| SCENARIO_1_SPAM_BURST | email-edge | Medium | mail-relay-01 | compromised_by (mail-relay-01 -> attacker-185.199.220.14) |
| SCENARIO_2_MALWARE_ATTACHMENT | email-edge | High | finance.user@example.com, finance.user@example.com | compromised_by (finance.user@example.com -> attacker-185.199.220.14) |
| SCENARIO_3_UNAUTHORIZED_ACCESS | identity | High | workstation-admin | compromised_by (workstation-admin -> attacker-185.199.220.14) |
| SCENARIO_4_BEC_ATTEMPT | identity | Critical | ceo-mailbox@example.com, ceo-mailbox@example.com | modifies (ceo-mailbox@example.com -> attacker-185.199.220.14); compromised_by (ceo-mailbox@example.com -> attacker-185.199.220.14) |
| SCENARIO_5_OAUTH_ABUSE | identity | High | rogue-consent-app, tenant-identity-plane | compromised_by (rogue-consent-app -> attacker-185.199.220.14); issues_token_to (tenant-identity-plane -> rogue-consent-app) |
| SCENARIO_6_VENDOR_COMPROMISE | supply-chain | Critical | vendor-automation-user, vendor-integration-gateway | compromised_by (vendor-automation-user -> attacker-185.199.220.14); targets (vendor-integration-gateway -> attacker-185.199.220.14) |
| SCENARIO_7_INSIDER_MISUSE | cloud | Critical | privileged.analyst@example.com, staging-bucket | exfiltrates_to (privileged.analyst@example.com -> staging-bucket); compromised_by (privileged.analyst@example.com -> attacker-185.199.220.14) |
| SCENARIO_8_TOKEN_REPLAY_IMPOSSIBLE_TRAVEL | identity | Critical | dev-lead-primary, dev_lead@example.com | replayed_by (dev-lead-primary -> attacker-185.199.220.14); spoofs_identity_of (dev-lead-primary -> dev_lead@example.com) |
| SCENARIO_9_LATERAL_MOVEMENT_OAUTH | cloud | Critical | analyticssync, finance_lead@example.com, hr_manager@example.com | moves_laterally_to (analyticssync -> finance_lead@example.com); moves_laterally_to (analyticssync -> hr_manager@example.com); compromised_by (analyticssync -> attacker-185.199.220.14) |
| SCENARIO_10_SERVICE_PRINCIPAL_HIJACK | cloud | Critical | sp-prod-backup-manager, production-backup-plane | compromised_by (sp-prod-backup-manager -> attacker-185.199.220.14); executes_on (sp-prod-backup-manager -> production-backup-plane) |
| SCENARIO_11_K8S_SIDECAR_BREAKOUT | container | Critical | payments-sidecar, k8s-node-01 | moves_laterally_to (payments-sidecar -> k8s-node-01); compromised_by (payments-sidecar -> attacker-185.199.220.14) |
| SCENARIO_12_SUPPLY_CHAIN_POISONING | supply-chain | Critical | release-pipeline, malicious-build | deploys_artifact_to (malicious-build -> release-pipeline); compromised_by (release-pipeline -> attacker-185.199.220.14) |
| SCENARIO_13_ZERO_DAY_EXPLOIT | runtime | Critical | profile-api, db-admin-01 | compromised_by (profile-api -> attacker-185.199.220.14); moves_laterally_to (profile-api -> db-admin-01); creates_persistence_in (profile-api -> db-admin-01) |
| SCENARIO_14_HYBRID_CLOUD_RANSOMWARE | ransomware | Critical | fileserver-02, prod-app-01, customer-records | encrypts (fileserver-02 -> attacker-185.199.220.14); encrypts (prod-app-01 -> attacker-185.199.220.14); encrypts (customer-records -> attacker-185.199.220.14) |
| SCENARIO_15_CROSS_TENANT_FEDERATION_ABUSE | identity-federation | Critical | tenant-a-to-tenant-b, contractor_jane@tenantA.com, shadow-app | abused_by (tenant-a-to-tenant-b -> attacker-185.199.220.14); assumes_role_in (contractor_jane@tenantA.com -> tenant-a-to-tenant-b); creates_persistence_in (shadow-app -> tenant-a-to-tenant-b) |
| SCENARIO_16_OIDC_SIGNING_KEY_THEFT | identity-core | Critical | idp.example.com, ceo@example.com, finance_lead@example.com | signing_key_stolen_by (idp.example.com -> attacker-185.199.220.14); issues_token_to (idp.example.com -> ceo@example.com); moves_laterally_to (ceo@example.com -> finance_lead@example.com) |
| SCENARIO_17_HARDWARE_ROOT_OF_TRUST_COMPROMISE | hardware-trust | Critical | node-7, node-7, node-7, prod-db-01, shadow-db | extracts_key_from (node-7 -> attacker-185.199.220.14); forges_attestation_for (node-7 -> shadow-db); spoofs_identity_of (shadow-db -> prod-db-01) |

## Conceptual Flow

- Attacker infrastructure compromises user, app, workload, pipeline, identity, and hardware surfaces across the full 17-scenario universe.
- Identity abuse escalates from credentials to OAuth, federation, and finally OIDC signing-key theft.
- Cloud and workload abuse expands through service principals, Kubernetes breakout, runtime compromise, ransomware, and hardware trust collapse.
- Hardware compromise in Scenario 17 invalidates the trust assumptions that software and cloud controls depend on.
- Mission Control should treat the graph as a single ontology whose terminal path ends at total identity, cloud, and hardware dominance.

## Mission Control Usage Notes

- Machine-readable graph: `incident_attack_graph.json`
- Human-readable graph map: `incident_attack_graph.md`
- Use scenario nodes as drill-down anchors and shared entity nodes as correlation pivots in visualizations.
- Use relationship frequency and criticality to rank likely blast-radius paths across identity, cloud, runtime, supply chain, and hardware trust layers.
