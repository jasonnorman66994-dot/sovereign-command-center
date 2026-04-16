# Azure Networking Decision Matrix

Quick reference matrix to help select the right Azure networking resource based on your scenario.

---

## Load Balancing & Traffic Distribution

| Scenario | Recommended Resource | Notes |
|---|---|---|
| Distribute TCP/UDP traffic across VMs | Load Balancer | Layer 4, simple and cost-effective |
| Distribute HTTP/HTTPS traffic with SSL termination | Application Gateway | Layer 7, supports WAF and URL routing |
| Global traffic distribution across regions | Traffic Manager | DNS-based, uses performance, priority, or geographic routing |

---

## Security & Access Control

| Scenario | Recommended Resource | Notes |
|---|---|---|
| Control inbound/outbound traffic at subnet/NIC level | Network Security Group (NSG) | Lightweight, rule-based filtering |
| Centralized firewall with logging and threat protection | Azure Firewall | Scalable, managed service |
| Restrict subnet access to specific Azure services | Service Endpoint Policies | Fine-grained control for service access |

---

## Connectivity & Hybrid Integration

| Scenario | Recommended Resource | Notes |
|---|---|---|
| Connect Azure VNets to on-premises via VPN | VPN Gateway | Secure, cost-effective, but limited throughput |
| High-throughput, low-latency private connection | ExpressRoute Circuit & Gateway | Dedicated line, ideal for enterprise workloads |
| Provide outbound internet connectivity with static IP | NAT Gateway | Simplifies outbound traffic management |

---

## Core Networking & DNS

| Scenario | Recommended Resource | Notes |
|---|---|---|
| Define private IP space and isolate workloads | Virtual Network (VNet) | Foundation of Azure networking |
| Attach VMs to subnets | Network Interface (NIC) | Connects VMs to VNets |
| Provide external connectivity to resources | Public IP Address | Required for internet-facing services |
| Host DNS records for custom domains | DNS Zone | Supports internal and external resolution |

---

## Specialized Networking

| Scenario | Recommended Resource | Notes |
|---|---|---|
| Connect VNets across regions/subscriptions | Virtual Network Peering | Seamless, low-latency connectivity |
| Provide private access to Azure services | Private Link Service | Eliminates public exposure |
| Mirror traffic for monitoring/security tools | Virtual Network Tap | Useful for deep packet inspection |

---

## Key Takeaways

- **Load Balancing**: Use Load Balancer for simple traffic distribution, Application Gateway for web apps, and Traffic Manager for global routing.
- **Security**: Secure workloads with NSGs for basic rules and Azure Firewall for enterprise-grade protection.
- **Hybrid Connectivity**: Choose VPN Gateway for cost-effective hybrid connectivity, ExpressRoute for mission-critical performance.
- **Foundation**: Build with VNets, NICs, and Public IPs, then extend with DNS Zones and specialized services.

---

## Decision Flow

```text
Start: What do you need to accomplish?

├─ Load balancing across VMs?
│  └─ TCP/UDP → Load Balancer
│  └─ HTTP/HTTPS → Application Gateway
│  └─ Global regions → Traffic Manager
│
├─ Secure traffic?
│  └─ Subnet/NIC level → NSG
│  └─ Enterprise-grade → Azure Firewall
│  └─ Service-level → Service Endpoint Policies
│
├─ Connect hybrid/on-premises?
│  └─ Cost-effective VPN → VPN Gateway
│  └─ High-throughput → ExpressRoute
│  └─ Egress IP control → NAT Gateway
│
├─ DNS or domain resolution?
│  └─ Custom domains → DNS Zone
│
└─ Advanced connectivity?
   └─ Multi-region VNets → VNet Peering
   └─ Private service access → Private Link
   └─ Traffic analysis → VNet Tap
```

---

## Quick Selection Guide

- **For startups and small teams:**
  - VNet + NSG + Load Balancer + Public IP

- **For mid-market with web apps:**
  - VNet + NSG + Application Gateway + DNS Zone + WAF

- **For enterprises with hybrid needs:**
  - VNet + NSG + Azure Firewall + ExpressRoute + VPN Gateway (redundancy)

- **For global, multi-region workloads:**
  - Multiple VNets + Traffic Manager + VNet Peering + NAT Gateways
