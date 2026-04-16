# Azure Hub-Spoke Enterprise Architecture Plan

**Date:** April 16, 2026  
**Version:** 1.0  
**Scope:** Enterprise-grade hub-spoke topology with disaster recovery and multi-region extension capabilities

---

## Executive Summary

This document outlines an enterprise-ready hub-spoke architecture for Azure, designed to:

- Centralize security and compliance controls (hub)
- Isolate workloads for independent scaling and management (spokes)
- Support hybrid connectivity via VPN Gateway and ExpressRoute
- Enable private access to Azure services via Private Link
- Provide business continuity and disaster recovery capabilities

---

## Architecture Components

### Hub VNet Tier

| Component | Service | Purpose | SKU/Size |
|---|---|---|---|
| **VNet** | Azure Virtual Network | Central hub network for shared services | 10.0.0.0/16 |
| **Subnets** | Subnets | Gateway, Firewall, Bastion, Management | See detailed subnets below |
| **Firewall** | Azure Firewall | Centralized egress and ingress inspection | Standard or Premium tier |
| **VPN Gateway** | VPN Gateway | On-premises connectivity | VpnGw4 or VpnGw5 |
| **Bastion** | Azure Bastion | Secure VM access without public IPs | Standard tier |
| **DNS Servers** | Private DNS Zone | Private name resolution for spokes | Zone per domain |
| **Application Gateway** | Application Gateway | Layer 7 load balancing and WAF | WAF_v2 |
| **NAT Gateway** | NAT Gateway | Outbound internet from hub services | Standard |

### Spoke VNets Tier (Workload Isolation)

| Component | Service | Purpose | Notes |
|---|---|---|---|
| **VNet** | Azure Virtual Network | Isolated workload network | 10.1.0.0/16, 10.2.0.0/16, etc. |
| **Subnets** | Subnets | App tier, data tier, etc. | Per workload requirements |
| **NSGs** | Network Security Groups | Workload-level micro-segmentation | Per subnet/tier |
| **Route Tables** | User-Defined Routes | Force traffic through hub firewall | To 0.0.0.0/0 → Firewall |
| **NAT Gateway** | NAT Gateway | Deterministic outbound IPs per spoke | Optional per spoke |
| **Private Endpoints** | Private Link | Private access to PaaS services | For storage, databases, etc. |

### Connectivity Layer

| Component | Service | Purpose | Backup |
|---|---|---|---|
| **VNet Peering** | VNet Peering | Hub ↔ Spoke connectivity | Bidirectional, no transitive peering |
| **VPN Gateway** | VPN Gateway (S2S) | On-premises hybrid connectivity | Primary with redundancy |
| **ExpressRoute** | ExpressRoute Circuit & Gateway | High-throughput private link | Backup to VPN Gateway |
| **Site Recovery** | Azure Site Recovery | Disaster recovery orchestration | For failover automation |

---

## Subnet Design

### Hub VNet Subnets (10.0.0.0/16)

| Subnet | CIDR | Services | NSG Rules |
|---|---|---|---|
| GatewaySubnet | 10.0.0.0/24 | VPN Gateway, ExpressRoute Gateway | Allow gateway-to-gateway comms only |
| FirewallSubnet | 10.0.1.0/24 | Azure Firewall | Allow all internal traffic |
| AzureBastionSubnet | 10.0.2.0/24 | Azure Bastion | Allow inbound RDP/SSH from internet |
| ManagementSubnet | 10.0.3.0/24 | Management VMs, monitoring | Allow from admin networks only |
| AppGatewaySubnet | 10.0.4.0/24 | Application Gateway (WAF) | Allow HTTP/HTTPS from internet |
| PrivateLinkSubnet | 10.0.5.0/24 | Private endpoints to PaaS | Allow from spoke subnets |

### Spoke VNet Subnets (Example: 10.1.0.0/16)

| Subnet | CIDR | Services | NSG Rules |
|---|---|---|---|
| ApplicationSubnet | 10.1.0.0/24 | Web servers, app tier VMs | Allow from ALB only |
| DataSubnet | 10.1.1.0/24 | Databases, cache layers | Allow from app tier only |
| IntegrationSubnet | 10.1.2.0/24 | Logic apps, event hubs | Allow spoke-to-spoke via hub |

---

## Routing & Traffic Flow

### Egress Flow (Spoke → Internet)

```text
Spoke VM → UDR (0.0.0.0/0 → Firewall) → Hub Firewall → Internet
          (Denied if firewall rule blocks)
```

### Ingress Flow (Internet → Spoke)

```text
Internet → Application Gateway (WAF) → Hub Firewall → Spoke App Gateway/ALB → VMs
          (TLS termination)           (DNAT rule)
```

### On-Premises Flow

```text
On-Prem → VPN Gateway (Site-to-Site) → Hub → Spoke (UDR via firewall)
                      ↓ (backup)
          ExpressRoute Gateway → Hub → Spoke
```

---

## Security Posture

### Network-Level

- **NSGs**: Micro-segmentation at subnet level (hub) and workload level (spokes)
- **Azure Firewall**: Centralized inspection with:
  - FQDN filtering and URL filtering
  - Threat intelligence integration
  - Logging to Log Analytics
  - DDoS protection

### Application-Level

- **Application Gateway WAF**: Layer 7 protection with:
  - OWASP Top 10 rule sets
  - Custom rules per workload
  - Rate limiting and bot detection

### Identity & Access

- **Private Endpoints**: Private access to PaaS services without public IPs
- **Bastion**: Secure VM access without exposing RDP/SSH ports
- **Managed Identities**: For RBAC-based service-to-service authentication

### Compliance

- **Audit Logging**: All firewall, NSG, and WAF logs sent to Log Analytics
- **Network Watcher**: Flow logs for traffic analysis and threat detection
- **Azure Policy**: Enforce network security standards (e.g., no public IPs, encryption-in-transit)

---

## Disaster Recovery & High Availability

### Regional Redundancy

- **Hub**: Single region (primary), optional secondary region for DR
- **Spokes**: Can be spread across multiple regions with Traffic Manager for global routing
- **Failover**: VPN Gateway and ExpressRoute with BGP failover

### Business Continuity

| RTO | RPO | Mechanism |
|---|---|---|
| 15 min | 5 min | Azure Site Recovery for VMs + manual RTO for networking |
| 30 min | 0 | Automated failover for stateless services with ALB |

### Backup

- Azure Backup for VM workloads and databases
- Managed backup for PaaS services (databases, storage)

---

## Scaling & Growth

### Adding New Spokes

1. Create new VNet (e.g., 10.2.0.0/16 for Spoke-2)
2. Create peering from new spoke to hub
3. Update hub's Azure Firewall rules (if needed)
4. Configure UDRs to route via hub firewall
5. Optionally: Add Private DNS CNAME records for service discovery

### Multi-Region Extension

- Deploy identical hub-spoke in secondary region
- Use Traffic Manager for global routing
- Replicate traffic rules to secondary firewall
- Configure ExpressRoute/VPN failover between regions

---

## Cost Optimization

| Component | Cost Driver | Optimization |
|---|---|---|
| Azure Firewall | Data processing, rules complexity | Consolidate rules, use network rules over app rules |
| VPN Gateway | Bandwidth, tunnel count | Use ExpressRoute for consistent throughput |
| VNet Peering | Inbound/outbound data transfer | Local peering is free, cross-region charged |
| Private Link | Endpoint count | Consolidate services or use shared endpoints |
| NAT Gateway | Outbound data | Use selective NAT only for required services |

---

## Deployment Phases

### Phase 1: Foundation (Week 1)

- Create hub VNet with Gateway, Firewall, and Bastion subnets
- Deploy Azure Firewall with basic rules
- Deploy VPN Gateway (single region)

### Phase 2: Workload Spokes (Week 2–3)

- Create 2–3 spoke VNets with peering to hub
- Deploy NSGs and UDRs
- Deploy sample workloads (VMs, databases)

### Phase 3: Hybrid Connectivity (Week 4)

- Configure VPN Gateway for on-premises connectivity
- Set up ExpressRoute (if available)
- Test failover scenarios

### Phase 4: DR & Hardening (Week 5–6)

- Deploy Azure Site Recovery
- Implement Azure Policy compliance checks
- Configure monitoring and alerting

---

## IaC Deliverables

- **Bicep Templates**: `main.bicep`, `hub.bicep`, `spoke.bicep`, `networking.bicep`, `security.bicep`
- **Terraform Modules**: `hub/`, `spoke/`, `networking/`, `security/`
- **Parameter Files**: `hub.parameters.json`, `spoke.parameters.json`
- **Terraform Variables**: `variables.tf`, `terraform.tfvars.example`

---

## Next Steps

1. Customize CIDR ranges for your environment
2. Define firewall rules and NSG rules per workload
3. Generate Bicep/Terraform templates from plan
4. Validate templates against Azure Policy requirements
5. Deploy to non-production environment for testing
6. Plan cutover strategy for production
