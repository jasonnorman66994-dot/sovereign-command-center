# Azure Hybrid Connectivity Failover Runbook

Version: 1.0  
Last Updated: 2026-04-16  
Audience: Cloud Operations, Network Engineering, Incident Response

---

## Purpose

Defines failover procedures between VPN Gateway and ExpressRoute for hybrid connectivity resilience.

---

## Reference Topology

- Primary path: ExpressRoute circuit and gateway
- Secondary path: Site-to-site VPN Gateway
- Routing: BGP preferred, static fallback only where required

---

## Trigger Conditions

Initiate failover when one or more occur:

- ExpressRoute BGP session down > 5 minutes
- Packet loss > 5% sustained for 10 minutes
- Latency exceeds application SLO threshold
- Circuit provider outage confirmed

---

## Prechecks

1. Confirm incident severity and impacted services.
2. Verify Azure gateway health in primary region.
3. Verify on-prem edge device state and BGP neighbor status.
4. Confirm VPN tunnel readiness.

Commands:

```powershell
Get-AzVirtualNetworkGateway -ResourceGroupName "rg-hub" -Name "scc-vng"
Get-AzVirtualNetworkGatewayConnection -ResourceGroupName "rg-hub"
```

---

## ExpressRoute to VPN Failover Procedure

### Step 1: Validate VPN Path

- Ensure VPN connection status is Connected.
- Validate routes learned from on-prem via BGP.

### Step 2: Reduce/Withdraw ExpressRoute Preference

- Lower local preference on on-prem router for ExpressRoute routes.
- Increase BGP preference for VPN route advertisements.

### Step 3: Confirm Traffic Shift

- Test application flows from Azure to on-prem and reverse.
- Validate critical ports and name resolution.

### Step 4: Stabilize and Monitor

- Monitor for 30 minutes minimum.
- Track packet loss, latency, and failed transactions.

---

## VPN to ExpressRoute Failback Procedure

1. Validate ExpressRoute circuit and BGP health.
2. Restore route preferences to primary design.
3. Confirm traffic return to ExpressRoute path.
4. Keep VPN active as warm standby.

---

## Verification Matrix

| Test | Source | Destination | Expected |
|---|---|---|---|
| DNS resolution | Azure spoke VM | On-prem DNS | Success < 200 ms |
| Database TCP | Azure app subnet | On-prem DB | Connection established |
| API call | On-prem app | Azure private endpoint | 200 OK |
| File transfer | Azure VM | On-prem share | Throughput within SLA |

---

## Communication Plan

- T+0: Declare incident and failover intent
- T+10: Confirm path shift complete
- T+30: Publish stability update
- T+60: Decision on sustained degraded mode or failback

Stakeholders:

- Network operations
- Application owners
- Security operations
- Service management

---

## Post-Incident Actions

- Capture timeline and route changes.
- Record root cause and provider details.
- Update runbook with lessons learned.
- Open preventive actions for capacity, monitoring, and automation.
