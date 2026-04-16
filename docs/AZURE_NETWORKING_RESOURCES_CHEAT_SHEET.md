# Azure Networking Resources Cheat Sheet

Quick reference to common Azure networking resources, their purpose, and when to use them.

## Core Networking Components

### Virtual Networks (VNets)

- Define private IP address space in Azure
- Use for isolating workloads and segmenting environments
- Foundation for all networking in Azure

### Network Interfaces (NICs)

- Attach VMs to subnets
- Can be associated with NSGs and public IPs
- Single point of attachment for VM networking

### Public IP Addresses

- Provide internet connectivity to VMs, load balancers, or gateways
- Use when external access is required
- Can be static or dynamic

---

## Security and Traffic Control

### Network Security Groups (NSGs)

- Firewall-like rules for inbound/outbound traffic
- Best for subnet- or NIC-level traffic filtering
- Stateful filtering at L3/L4

### Azure Firewalls

- Managed, scalable firewall service
- Use for centralized traffic inspection and logging
- Supports FQDN filtering, threat intelligence, and DNAT/SNAT

### Service Endpoint Policies

- Restrict which Azure services can be accessed from a subnet
- Scope-level policy enforcement for PaaS resources

---

## Load Balancing and Routing

### Load Balancers

- Distribute traffic across multiple VMs
- Layer 4 (TCP/UDP) balancing
- High availability and scale for workloads

### Application Gateways

- Layer 7 load balancer with SSL termination and WAF
- Ideal for web applications
- Supports URL-based, host-based, and path-based routing

### Route Tables

- Define custom routing rules
- Useful for directing traffic to on-premises or specific appliances
- Enable user-defined routes (UDRs) for hub-spoke topologies

---

## Connectivity and Hybrid Integration

### Virtual Network Gateways / VPN Gateways

- Connect VNets to on-premises networks via VPN
- Use for secure hybrid connectivity
- Support site-to-site, point-to-site, and VNet-to-VNet scenarios

### ExpressRoute Circuits & Gateways

- Private, dedicated connection to Azure
- Best for high-throughput, low-latency hybrid setups
- No internet traversal

### NAT Gateways

- Provide outbound internet connectivity with static IP
- Simplifies outbound traffic management
- Deterministic public IP for workloads

---

## DNS and Traffic Management

### DNS Zones

- Host DNS records for custom domains
- Use for internal or external name resolution
- Azure DNS provides high-performance authoritative DNS

### Traffic Manager Profiles

- Distribute traffic globally based on performance, priority, or geography
- Provides DNS-level load balancing and failover
- Multi-region high availability

---

## Specialized Networking

### Private Link Services

- Provide private connectivity to Azure services
- Use for secure access without exposing services publicly
- Private endpoint connectivity across subscriptions and tenants

### Virtual Network Peerings

- Connect VNets seamlessly
- Useful for multi-region or multi-subscription architectures
- Supports both VNet-to-VNet and global peering

### Virtual Network Taps

- Mirror traffic for monitoring and security tools
- Use for packet capture and IDS/IPS integration
- Non-intrusive traffic inspection

---

## Hub-Spoke Architecture Quick Reference

| Resource | Hub | Spoke | Notes |
|---|---|---|---|
| Virtual Networks | 1 central | 1 per workload | Hub centralizes services; spokes isolate workloads |
| Azure Firewall | Yes | No | Central inspection for all traffic flows |
| VPN/ExpressRoute Gateway | Yes | No | Single hybrid connectivity point for all spokes |
| Load Balancers | Optional | Common | Close to workloads for internal balancing |
| Application Gateways | Central ingress | Per-app optional | L7 routing at edge or per-spoke if needed |
| NSGs | Strict admin/control | Liberal app segmentation | Combine with firewall for defense-in-depth |
| Route Tables | Hub routing rules | UDRs to hub firewall | Forces traffic through inspection |
| NAT Gateways | Optional | Common | Deterministic egress from spokes |
| Public IPs | Firewall/gateway/bastion | Avoid on VMs | Minimize direct internet exposure |

---

## Key Takeaways

- **VNets are the foundation** of Azure networking
- **NSGs and Firewalls** secure traffic at different scopes
- **Load Balancers and Application Gateways** manage traffic distribution
- **Gateways and ExpressRoute** enable hybrid connectivity
- **DNS Zones and Traffic Manager** handle name resolution and global routing
- **Private Link and Peering** extend connectivity securely across boundaries
- **Hub-spoke topology** centralizes security and management while isolating workloads

---

## When to Use This Cheat Sheet

- Architecture planning and design reviews
- Azure audit and compliance assessments
- Troubleshooting network connectivity issues
- Onboarding new infrastructure teams
- Multi-region or hybrid-cloud scenarios

---

## Additional Resources

- [Azure Virtual Network documentation](https://learn.microsoft.com/en-us/azure/virtual-network/)
- [Network Security Best Practices](https://learn.microsoft.com/en-us/azure/security/fundamentals/network-best-practices)
- [Hub-Spoke Network Topology in Azure](https://learn.microsoft.com/en-us/azure/architecture/reference-architectures/hybrid-networking/hub-spoke)
