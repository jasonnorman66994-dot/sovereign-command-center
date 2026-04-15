# Campaign Launcher Manifest — 2026-04-14

Machine-runnable launcher profiles for Mission Control campaigns.

## Constraints

- safe_mode: True
- synthetic_only: True
- destructive_actions_forbidden: True
- authorized_scope_required: True

## Profiles

| ID | Mode | Safe | Synthetic | Sequence Length |
|---|---|---|---|---:|
| single-scenario_1_spam_burst | single_scenario | True | True | 1 |
| single-scenario_2_malware_attachment | single_scenario | True | True | 1 |
| single-scenario_3_unauthorized_access | single_scenario | True | True | 1 |
| single-scenario_4_bec_attempt | single_scenario | True | True | 1 |
| single-scenario_5_oauth_abuse | single_scenario | True | True | 1 |
| single-scenario_6_vendor_compromise | single_scenario | True | True | 1 |
| single-scenario_7_insider_misuse | single_scenario | True | True | 1 |
| single-scenario_8_token_replay_impossible_travel | single_scenario | True | True | 1 |
| single-scenario_9_lateral_movement_oauth | single_scenario | True | True | 1 |
| single-scenario_10_service_principal_hijack | single_scenario | True | True | 1 |
| single-scenario_11_k8s_sidecar_breakout | single_scenario | True | True | 1 |
| single-scenario_12_supply_chain_poisoning | single_scenario | True | True | 1 |
| single-scenario_13_zero_day_exploit | single_scenario | True | True | 1 |
| single-scenario_14_hybrid_cloud_ransomware | single_scenario | True | True | 1 |
| single-scenario_15_cross_tenant_federation_abuse | single_scenario | True | True | 1 |
| single-scenario_16_oidc_signing_key_theft | single_scenario | True | True | 1 |
| single-scenario_17_hardware_root_of_trust_compromise | single_scenario | True | True | 1 |
| chain-01 | multi_scenario_chain | True | True | 4 |
| chain-02 | multi_scenario_chain | True | True | 4 |
| chain-03 | multi_scenario_chain | True | True | 3 |
| full-spectrum-01 | full_spectrum_campaign | True | True | 20 |

## Example Launch Intents

- Single scenario: `python -m shadow_toolkit.cli campaign --mode single --scenario SCENARIO_3_UNAUTHORIZED_ACCESS`
- Chain campaign: `python -m shadow_toolkit.cli campaign --mode chain --chain-id chain-01`
- Full spectrum: `python -m shadow_toolkit.cli campaign --mode full-spectrum --start 1 --end 20 --safety simulated-synthetic-safe`

