from datetime import datetime
import json
import re

ANALYTICS_FILE = "cross_scenario_analytics.json"
KPI_FILE = "chain_kpis.json"
OUT_JSON = "incident_attack_graph.json"
OUT_MD = "incident_attack_graph.md"

NODE_TYPES = [
    "Scenario",
    "User",
    "Mailbox",
    "Session",
    "Identity Provider",
    "Federation Trust",
    "OAuth App",
    "Service Principal",
    "Device / Node",
    "Container / Pod",
    "VM / Workload",
    "Pipeline / Artifact",
    "Storage Bucket / Blob",
    "Network Endpoint",
    "TPM / Secure Enclave",
    "Hardware Attestation",
    "Attacker Infrastructure",
    "Event / Log Entry",
]

RELATIONSHIP_TYPES = [
    "compromised_by",
    "issues_token_to",
    "assumes_role_in",
    "executes_on",
    "exfiltrates_to",
    "modifies",
    "creates_persistence_in",
    "moves_laterally_to",
    "forges_attestation_for",
    "extracts_key_from",
    "deploys_artifact_to",
    "encrypts",
    "spoofs_identity_of",
    "abused_by",
    "replayed_by",
    "signing_key_stolen_by",
    "targets",
    "observed_in",
    "validated_by",
]

ATTACKER_NODE = {
    "id": "infra:attacker-185.199.220.14",
    "type": "Attacker Infrastructure",
    "label": "Attacker Infrastructure (185.199.220.14)",
    "layer": "attacker",
    "criticality": "Critical",
}

SCENARIO_ONTOLOGY = {
    "SCENARIO_1_SPAM_BURST": {
        "title": "Spam Burst / Relay Probing",
        "layer": "email-edge",
        "description": "Inbound spam burst and relay probing against the monitored tenant edge.",
        "entities": [
            {"id": "endpoint:mail-relay-01", "type": "Network Endpoint", "label": "mail-relay-01"},
        ],
        "relationships": [
            {"source": "endpoint:mail-relay-01", "type": "compromised_by", "target": ATTACKER_NODE["id"], "note": "Spam and relay probing pressure the email edge."},
        ],
    },
    "SCENARIO_2_MALWARE_ATTACHMENT": {
        "title": "Malware Attachment Attempt",
        "layer": "email-edge",
        "description": "Malware-laced message delivery targeting user inbox workflows.",
        "entities": [
            {"id": "user:finance.user@example.com", "type": "User", "label": "finance.user@example.com"},
            {"id": "mailbox:finance.user@example.com", "type": "Mailbox", "label": "Finance User Mailbox"},
        ],
        "relationships": [
            {"source": "mailbox:finance.user@example.com", "type": "compromised_by", "target": ATTACKER_NODE["id"], "note": "Attachment delivery targets inbox execution paths."},
        ],
    },
    "SCENARIO_3_UNAUTHORIZED_ACCESS": {
        "title": "Unauthorized Access / Credential Compromise",
        "layer": "identity",
        "description": "Credential compromise enables unauthorized access and suspicious session start.",
        "entities": [
            {"id": "user:workstation-admin", "type": "User", "label": "workstation-admin"},
        ],
        "relationships": [
            {"source": "user:workstation-admin", "type": "compromised_by", "target": ATTACKER_NODE["id"], "note": "Credential stuffing pattern leads to account compromise."},
        ],
    },
    "SCENARIO_4_BEC_ATTEMPT": {
        "title": "Business Email Compromise Attempt",
        "layer": "identity",
        "description": "Mailbox takeover and message manipulation drive financial fraud risk.",
        "entities": [
            {"id": "mailbox:ceo-mailbox@example.com", "type": "Mailbox", "label": "CEO Mailbox"},
            {"id": "user:ceo-mailbox@example.com", "type": "User", "label": "ceo-mailbox@example.com"},
        ],
        "relationships": [
            {"source": "mailbox:ceo-mailbox@example.com", "type": "modifies", "target": ATTACKER_NODE["id"], "note": "Reply-to and mailbox rules are altered during BEC."},
            {"source": "user:ceo-mailbox@example.com", "type": "compromised_by", "target": ATTACKER_NODE["id"], "note": "Executive identity takeover drives fraud operations."},
        ],
    },
    "SCENARIO_5_OAUTH_ABUSE": {
        "title": "OAuth Consent Abuse",
        "layer": "identity",
        "description": "Rogue OAuth application gains privileged delegated access.",
        "entities": [
            {"id": "oauth:rogue-consent-app", "type": "OAuth App", "label": "Rogue OAuth Consent App"},
            {"id": "idp:tenant-identity-plane", "type": "Identity Provider", "label": "Tenant Identity Plane"},
        ],
        "relationships": [
            {"source": "oauth:rogue-consent-app", "type": "compromised_by", "target": ATTACKER_NODE["id"], "note": "Unverified app uses high-risk delegated scopes."},
            {"source": "idp:tenant-identity-plane", "type": "issues_token_to", "target": "oauth:rogue-consent-app", "note": "Consent flow grants attacker-controlled token access."},
        ],
    },
    "SCENARIO_6_VENDOR_COMPROMISE": {
        "title": "Vendor Compromise",
        "layer": "supply-chain",
        "description": "Downstream fraud path begins with compromised vendor automation access.",
        "entities": [
            {"id": "user:vendor-automation-user", "type": "User", "label": "vendor-automation-user"},
            {"id": "endpoint:vendor-integration-gateway", "type": "Network Endpoint", "label": "Vendor Integration Gateway"},
        ],
        "relationships": [
            {"source": "user:vendor-automation-user", "type": "compromised_by", "target": ATTACKER_NODE["id"], "note": "Vendor automation identity seeds downstream compromise."},
            {"source": "endpoint:vendor-integration-gateway", "type": "targets", "target": ATTACKER_NODE["id"], "note": "Vendor access path becomes the attacker ingress route."},
        ],
    },
    "SCENARIO_7_INSIDER_MISUSE": {
        "title": "Insider Misuse",
        "layer": "cloud",
        "description": "Privileged insider abuse expands access and stages data for exfiltration.",
        "entities": [
            {"id": "user:privileged.analyst@example.com", "type": "User", "label": "privileged.analyst@example.com"},
            {"id": "storage:staging-bucket", "type": "Storage Bucket / Blob", "label": "staging-bucket"},
        ],
        "relationships": [
            {"source": "user:privileged.analyst@example.com", "type": "exfiltrates_to", "target": "storage:staging-bucket", "note": "Insider stages data into controlled storage paths."},
            {"source": "user:privileged.analyst@example.com", "type": "compromised_by", "target": ATTACKER_NODE["id"], "note": "Insider or coerced privileged access drives data staging."},
        ],
    },
    "SCENARIO_8_TOKEN_REPLAY_IMPOSSIBLE_TRAVEL": {
        "title": "Token Replay and Impossible Travel",
        "layer": "identity",
        "description": "Session hijack uses replayed tokens across impossible travel conditions.",
        "entities": [
            {"id": "session:dev-lead-primary", "type": "Session", "label": "dev_lead primary session"},
            {"id": "user:dev_lead@example.com", "type": "User", "label": "dev_lead@example.com"},
        ],
        "relationships": [
            {"source": "session:dev-lead-primary", "type": "replayed_by", "target": ATTACKER_NODE["id"], "note": "Bearer token replay drives the impossible travel signal."},
            {"source": "session:dev-lead-primary", "type": "spoofs_identity_of", "target": "user:dev_lead@example.com", "note": "Attacker reuses valid session state to impersonate the user."},
        ],
    },
    "SCENARIO_9_LATERAL_MOVEMENT_OAUTH": {
        "title": "Lateral Movement via OAuth App",
        "layer": "cloud",
        "description": "OAuth application abuse impersonates multiple users and pivots across cloud data paths.",
        "entities": [
            {"id": "oauth:analyticssync", "type": "OAuth App", "label": "AnalyticsSync"},
            {"id": "user:finance_lead@example.com", "type": "User", "label": "finance_lead@example.com"},
            {"id": "user:hr_manager@example.com", "type": "User", "label": "hr_manager@example.com"},
        ],
        "relationships": [
            {"source": "oauth:analyticssync", "type": "moves_laterally_to", "target": "user:finance_lead@example.com", "note": "OAuth token abuse pivots across multiple identities."},
            {"source": "oauth:analyticssync", "type": "moves_laterally_to", "target": "user:hr_manager@example.com", "note": "OAuth app laterally accesses additional users."},
            {"source": "oauth:analyticssync", "type": "compromised_by", "target": ATTACKER_NODE["id"], "note": "Attacker-controlled app becomes a lateral movement hub."},
        ],
    },
    "SCENARIO_10_SERVICE_PRINCIPAL_HIJACK": {
        "title": "Service Principal Hijack",
        "layer": "cloud",
        "description": "Compromised service principal seizes production workload permissions.",
        "entities": [
            {"id": "spn:sp-prod-backup-manager", "type": "Service Principal", "label": "sp-prod-backup-manager"},
            {"id": "workload:production-backup-plane", "type": "VM / Workload", "label": "Production Backup Plane"},
        ],
        "relationships": [
            {"source": "spn:sp-prod-backup-manager", "type": "compromised_by", "target": ATTACKER_NODE["id"], "note": "Service principal compromise unlocks workload actions."},
            {"source": "spn:sp-prod-backup-manager", "type": "executes_on", "target": "workload:production-backup-plane", "note": "Hijacked service principal operates directly on production workloads."},
        ],
    },
    "SCENARIO_11_K8S_SIDECAR_BREAKOUT": {
        "title": "Kubernetes Sidecar Breakout",
        "layer": "container",
        "description": "Container breakout crosses the pod boundary and reaches the underlying node.",
        "entities": [
            {"id": "pod:payments-sidecar", "type": "Container / Pod", "label": "payments-sidecar"},
            {"id": "node:k8s-node-01", "type": "Device / Node", "label": "k8s-node-01"},
        ],
        "relationships": [
            {"source": "pod:payments-sidecar", "type": "moves_laterally_to", "target": "node:k8s-node-01", "note": "Breakout escapes container isolation into the node."},
            {"source": "pod:payments-sidecar", "type": "compromised_by", "target": ATTACKER_NODE["id"], "note": "Attacker gains runtime control of the sidecar path."},
        ],
    },
    "SCENARIO_12_SUPPLY_CHAIN_POISONING": {
        "title": "CI/CD Pipeline Poisoning",
        "layer": "supply-chain",
        "description": "Malicious artifact drift enters production through poisoned automation.",
        "entities": [
            {"id": "pipeline:release-pipeline", "type": "Pipeline / Artifact", "label": "release-pipeline"},
            {"id": "artifact:malicious-build", "type": "Pipeline / Artifact", "label": "malicious-build"},
        ],
        "relationships": [
            {"source": "artifact:malicious-build", "type": "deploys_artifact_to", "target": "pipeline:release-pipeline", "note": "Poisoned artifact contaminates the release path."},
            {"source": "pipeline:release-pipeline", "type": "compromised_by", "target": ATTACKER_NODE["id"], "note": "Automation trust is subverted by attacker-controlled artifact flow."},
        ],
    },
    "SCENARIO_13_ZERO_DAY_EXPLOIT": {
        "title": "Zero-Day Runtime Exploit",
        "layer": "runtime",
        "description": "Public-facing service compromise expands into runtime control, exfiltration, and persistence.",
        "entities": [
            {"id": "service:profile-api", "type": "VM / Workload", "label": "profile-api"},
            {"id": "node:db-admin-01", "type": "Device / Node", "label": "db-admin-01"},
        ],
        "relationships": [
            {"source": "service:profile-api", "type": "compromised_by", "target": ATTACKER_NODE["id"], "note": "Zero-day exploitation gains code execution in the public service."},
            {"source": "service:profile-api", "type": "moves_laterally_to", "target": "node:db-admin-01", "note": "Runtime compromise pivots laterally to administrative data paths."},
            {"source": "service:profile-api", "type": "creates_persistence_in", "target": "node:db-admin-01", "note": "Persistence follows successful runtime compromise."},
        ],
    },
    "SCENARIO_14_HYBRID_CLOUD_RANSOMWARE": {
        "title": "Hybrid-Cloud Ransomware",
        "layer": "ransomware",
        "description": "Cross-environment encryption strikes on-prem systems, cloud VMs, Kubernetes workloads, and storage.",
        "entities": [
            {"id": "node:fileserver-02", "type": "Device / Node", "label": "fileserver-02"},
            {"id": "workload:prod-app-01", "type": "VM / Workload", "label": "prod-app-01"},
            {"id": "storage:customer-records", "type": "Storage Bucket / Blob", "label": "customer-records"},
        ],
        "relationships": [
            {"source": "node:fileserver-02", "type": "encrypts", "target": ATTACKER_NODE["id"], "note": "On-premise host is encrypted by attacker payloads."},
            {"source": "workload:prod-app-01", "type": "encrypts", "target": ATTACKER_NODE["id"], "note": "Cloud workloads are encrypted under the same detonation path."},
            {"source": "storage:customer-records", "type": "encrypts", "target": ATTACKER_NODE["id"], "note": "Object storage is rewritten and effectively encrypted."},
        ],
    },
    "SCENARIO_15_CROSS_TENANT_FEDERATION_ABUSE": {
        "title": "Cross-Tenant Federation Abuse",
        "layer": "identity-federation",
        "description": "Federation trust abuse enables privileged cross-tenant takeover.",
        "entities": [
            {"id": "federation:tenant-a-to-tenant-b", "type": "Federation Trust", "label": "Tenant A → Tenant B Federation Trust"},
            {"id": "user:contractor_jane@tenantA.com", "type": "User", "label": "contractor_jane@tenantA.com"},
            {"id": "spn:shadow-app", "type": "Service Principal", "label": "shadow-app"},
        ],
        "relationships": [
            {"source": "federation:tenant-a-to-tenant-b", "type": "abused_by", "target": ATTACKER_NODE["id"], "note": "Cross-tenant federation path is abused as a privilege bridge."},
            {"source": "user:contractor_jane@tenantA.com", "type": "assumes_role_in", "target": "federation:tenant-a-to-tenant-b", "note": "Federated identity assumes privileged control via the trust path."},
            {"source": "spn:shadow-app", "type": "creates_persistence_in", "target": "federation:tenant-a-to-tenant-b", "note": "Rogue service principal extends persistence in the federation plane."},
        ],
    },
    "SCENARIO_16_OIDC_SIGNING_KEY_THEFT": {
        "title": "Global Identity Provider Compromise",
        "layer": "identity-core",
        "description": "OIDC signing key theft collapses the trust anchor for all downstream identities.",
        "entities": [
            {"id": "idp:idp.example.com", "type": "Identity Provider", "label": "idp.example.com"},
            {"id": "user:ceo@example.com", "type": "User", "label": "ceo@example.com"},
            {"id": "mailbox:finance_lead@example.com", "type": "Mailbox", "label": "Finance Lead Mailbox"},
        ],
        "relationships": [
            {"source": "idp:idp.example.com", "type": "signing_key_stolen_by", "target": ATTACKER_NODE["id"], "note": "Attacker steals the IdP signing key and becomes the trust anchor."},
            {"source": "idp:idp.example.com", "type": "issues_token_to", "target": "user:ceo@example.com", "note": "Forged but valid tokens are minted for privileged identities."},
            {"source": "user:ceo@example.com", "type": "moves_laterally_to", "target": "mailbox:finance_lead@example.com", "note": "Forged identity pivots across cloud and SaaS services."},
        ],
    },
    "SCENARIO_17_HARDWARE_ROOT_OF_TRUST_COMPROMISE": {
        "title": "Hardware Root-of-Trust Compromise",
        "layer": "hardware-trust",
        "description": "TPM and Secure Enclave extraction destroy the deepest trust anchor in the environment.",
        "entities": [
            {"id": "node:node-7", "type": "Device / Node", "label": "node-7"},
            {"id": "tpm:node-7", "type": "TPM / Secure Enclave", "label": "node-7 TPM / Secure Enclave"},
            {"id": "attestation:node-7", "type": "Hardware Attestation", "label": "node-7 attestation"},
            {"id": "workload:prod-db-01", "type": "VM / Workload", "label": "prod-db-01"},
            {"id": "workload:shadow-db", "type": "VM / Workload", "label": "shadow-db"},
        ],
        "relationships": [
            {"source": "tpm:node-7", "type": "extracts_key_from", "target": ATTACKER_NODE["id"], "note": "Hardware-backed key material is extracted from the trust anchor."},
            {"source": "attestation:node-7", "type": "forges_attestation_for", "target": "workload:shadow-db", "note": "Forged attestation causes shadow workloads to appear trusted."},
            {"source": "workload:shadow-db", "type": "spoofs_identity_of", "target": "workload:prod-db-01", "note": "Cloned workload impersonates the production database tier."},
            {"source": "workload:shadow-db", "type": "exfiltrates_to", "target": ATTACKER_NODE["id"], "note": "Data leaves the cloned workload after disk decryption and trust bypass."},
            {"source": "node:node-7", "type": "compromised_by", "target": ATTACKER_NODE["id"], "note": "Node-level compromise reaches the hardware root of trust."},
        ],
    },
}


def load_json(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def scenario_sort_key(name):
    match = re.search(r"SCENARIO_?(\d+)", name or "")
    return int(match.group(1)) if match else 999


def severity_rank(level):
    return {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}.get(level, 0)


def terminal_scenario_entry(analytics_payload):
    ranked = sorted(
        analytics_payload.items(),
        key=lambda item: (
            scenario_sort_key(item[0]),
            len(item[1].get("signals", [])),
            len(item[1].get("actions", [])),
            severity_rank((item[1].get("risk_levels") or ["Low"])[0]),
        ),
        reverse=True,
    )
    return ranked[0] if ranked else (None, None)


def build_graph():
    analytics = load_json(ANALYTICS_FILE)
    kpis = load_json(KPI_FILE)
    nodes = {ATTACKER_NODE["id"]: ATTACKER_NODE}
    edges = []
    scenario_mappings = []

    for scenario_id in sorted(SCENARIO_ONTOLOGY.keys(), key=scenario_sort_key):
        definition = SCENARIO_ONTOLOGY[scenario_id]
        payload = analytics.get(scenario_id, {})
        risk = (payload.get("risk_levels") or ["Unknown"])[0]
        classification = (payload.get("classifications") or [definition["title"]])[0]
        response_latency = kpis.get("estimated_response_latency_minutes", {}).get(scenario_id)
        containment_latency = kpis.get("estimated_containment_latency_minutes", {}).get(scenario_id)
        signal_count = len(payload.get("signals", []))
        action_count = len(payload.get("actions", []))

        scenario_node = {
            "id": f"scenario:{scenario_id}",
            "type": "Scenario",
            "label": scenario_id,
            "title": definition["title"],
            "layer": definition["layer"],
            "risk": risk,
            "classification": classification,
            "signals": signal_count,
            "actions": action_count,
            "response_latency_minutes": response_latency,
            "containment_latency_minutes": containment_latency,
        }
        nodes[scenario_node["id"]] = scenario_node

        primary_entity_ids = []
        for entity in definition.get("entities", []):
            nodes.setdefault(entity["id"], entity)
            primary_entity_ids.append(entity["id"])
            edges.append({
                "source": scenario_node["id"],
                "relationship": "targets",
                "target": entity["id"],
                "note": f"{scenario_id} centers on {entity['label']}",
            })

        relationship_triplets = []
        for rel in definition.get("relationships", []):
            edges.append({
                "source": rel["source"],
                "relationship": rel["type"],
                "target": rel["target"],
                "note": rel.get("note", ""),
                "scenario_id": scenario_id,
            })
            relationship_triplets.append({
                "source": rel["source"],
                "relationship": rel["type"],
                "target": rel["target"],
                "note": rel.get("note", ""),
            })

        scenario_mappings.append({
            "scenario_id": scenario_id,
            "title": definition["title"],
            "layer": definition["layer"],
            "description": definition["description"],
            "classification": classification,
            "risk": risk,
            "primary_entities": primary_entity_ids,
            "relationships": relationship_triplets,
        })

    terminal_scenario, terminal_payload = terminal_scenario_entry(analytics)
    graph = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "ontology": {
            "node_types": NODE_TYPES,
            "relationship_types": RELATIONSHIP_TYPES,
        },
        "summary": {
            "scenario_count": len(scenario_mappings),
            "node_count": len(nodes),
            "edge_count": len(edges),
            "terminal_scenario": terminal_scenario,
            "terminal_classification": (
                (terminal_payload.get("classifications") or [None])[0]
                if terminal_payload else None
            ),
        },
        "nodes": sorted(nodes.values(), key=lambda node: (node.get("type", ""), node.get("id", ""))),
        "edges": sorted(edges, key=lambda edge: (edge.get("scenario_id", ""), edge["source"], edge["relationship"], edge["target"])),
        "scenario_mappings": scenario_mappings,
    }
    return graph


def write_markdown(graph):
    lines = [
        f"# Incident Attack Graph — {datetime.now().strftime('%Y-%m-%d')}\n\n",
        "This artifact defines the unified attack-surface ontology for all Mission Control scenarios and links every scenario into a single graph-based incident model.\n\n",
        "## Graph Summary\n\n",
        f"- Scenario coverage: {graph['summary']['scenario_count']}\n",
        f"- Node count: {graph['summary']['node_count']}\n",
        f"- Edge count: {graph['summary']['edge_count']}\n",
        f"- Terminal scenario: {graph['summary']['terminal_scenario']}\n\n",
        "## Node Types\n\n",
    ]

    for node_type in graph["ontology"]["node_types"]:
        lines.append(f"- {node_type}\n")

    lines.extend(["\n## Relationship Types\n\n"])
    for relationship_type in graph["ontology"]["relationship_types"]:
        lines.append(f"- {relationship_type}\n")

    lines.extend([
        "\n## Scenario-to-Graph Mapping\n\n",
        "| Scenario | Layer | Risk | Primary Entities | Core Relationships |\n",
        "|---|---|---|---|---|\n",
    ])

    for mapping in graph["scenario_mappings"]:
        entities = ", ".join(entity.split(":", 1)[1] for entity in mapping["primary_entities"])
        rels = "; ".join(
            f"{rel['relationship']} ({rel['source'].split(':', 1)[1]} -> {rel['target'].split(':', 1)[1]})"
            for rel in mapping["relationships"][:3]
        )
        lines.append(f"| {mapping['scenario_id']} | {mapping['layer']} | {mapping['risk']} | {entities} | {rels} |\n")

    lines.extend([
        "\n## Conceptual Flow\n\n",
        "- Attacker infrastructure compromises user, app, workload, pipeline, identity, and hardware surfaces across the full 17-scenario universe.\n",
        "- Identity abuse escalates from credentials to OAuth, federation, and finally OIDC signing-key theft.\n",
        "- Cloud and workload abuse expands through service principals, Kubernetes breakout, runtime compromise, ransomware, and hardware trust collapse.\n",
        "- Hardware compromise in Scenario 17 invalidates the trust assumptions that software and cloud controls depend on.\n",
        "- Mission Control should treat the graph as a single ontology whose terminal path ends at total identity, cloud, and hardware dominance.\n\n",
        "## Mission Control Usage Notes\n\n",
        f"- Machine-readable graph: `{OUT_JSON}`\n",
        f"- Human-readable graph map: `{OUT_MD}`\n",
        "- Use scenario nodes as drill-down anchors and shared entity nodes as correlation pivots in visualizations.\n",
        "- Use relationship frequency and criticality to rank likely blast-radius paths across identity, cloud, runtime, supply chain, and hardware trust layers.\n",
    ])

    with open(OUT_MD, "w", encoding="utf-8") as f:
        f.writelines(lines)


def main():
    graph = build_graph()
    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(graph, f, indent=2)
    write_markdown(graph)
    print(f"Wrote {OUT_JSON} and {OUT_MD}")


if __name__ == "__main__":
    main()