# Azure Network Troubleshooting & Diagnostics Playbook

**Version:** 1.0 | **Last Updated:** April 16, 2026 | **Audience:** Network Operations, DevOps, SRE

---

## Quick Diagnosis Flowchart

```text
┌─ Is VM reachable? ─ Yes ─ Check service/app logs
│                 No
│                  └─ VM running? ─ Yes ─ Check NIC & IP config
│                                No ─ Start VM, retry
└─ Network Security Group (NSG) blocking?
   └─ Check NSG rules (inbound/outbound)
   └─ Application Gateway rules? (WAF)
   └─ Firewall rules? (Azure Firewall)
   └─ Route Tables? (UDR redirecting traffic)
   └─ Peering status? (VNet-to-VNet connectivity)
```

---

## Scenario 1: VM Cannot Reach Internet

### Symptoms

- VM cannot download packages (apt-get, yum, pip fails)
- Outbound HTTP/HTTPS requests timeout
- DNS resolution works but external connectivity fails

### Diagnostic Steps

#### Step 1: Verify VM & NIC Status

```powershell
# Check VM state
$vm = Get-AzVM -ResourceGroupName "rg-prod" -Name "vm-web-01"
$vm.PowerState  # Should be 'VM running'

# Check attached NICs
$nics = Get-AzNetworkInterface -ResourceGroupName "rg-prod" | Where-Object { $_.VirtualMachine.Id -eq $vm.Id }
$nics | Select-Object Name, IpConfigurations
```

#### Step 2: Check NSG Rules

```powershell
# Get NSG applied to NIC
$nic = Get-AzNetworkInterface -Name "nic-web-01" -ResourceGroupName "rg-prod"
$nsgId = $nic.NetworkSecurityGroup.Id
$nsg = Get-AzNetworkSecurityGroup -ResourceId $nsgId

# List outbound rules
$nsg.SecurityRules | Where-Object { $_.Direction -eq "Outbound" } | 
  Select-Object Name, Protocol, SourceAddressPrefix, DestinationAddressPrefix, Access | 
  Format-Table

# Check if "DenyAllOutbound" or similar exists (DenyAll rules block by default)
```

#### Step 3: Check Route Tables

```powershell
# Get subnet and its route table
$subnet = Get-AzVirtualNetworkSubnetConfig -Name "AppSubnet" `
  -VirtualNetwork (Get-AzVirtualNetwork -Name "vnet-prod" -ResourceGroupName "rg-prod")

# List routes
if ($subnet.RouteTable) {
  $rt = Get-AzRouteTable -ResourceGroupName $subnet.RouteTable.ResourceGroupName `
    -Name ($subnet.RouteTable.Id -split '/')[-1]
  $rt.Routes | Select-Object Name, AddressPrefix, NextHopType, NextHopIpAddress | Format-Table
}
```

#### Step 4: Check Azure Firewall Rules

```powershell
# If hub-spoke topology with Azure Firewall
$firewall = Get-AzFirewall -ResourceGroupName "rg-hub" -Name "fw-hub-prod"

# Network rules (Layer 4)
$firewall.NetworkRuleCollections | ForEach-Object {
  $_ | Select-Object Name, Priority, @{N='Action';E={$_.Action.Type}}
}

# Application rules (Layer 7)
$firewall.ApplicationRuleCollections | ForEach-Object {
  $_ | Select-Object Name, Priority, @{N='Action';E={$_.Action.Type}}
}
```

#### Step 5: Verify NAT Gateway Configuration

```powershell
# Check if NAT Gateway is configured
$subnet = Get-AzVirtualNetworkSubnetConfig -Name "AppSubnet" `
  -VirtualNetwork (Get-AzVirtualNetwork -Name "vnet-prod" -ResourceGroupName "rg-prod")

if ($subnet.NatGateway) {
  $natGateway = Get-AzNatGateway -ResourceId $subnet.NatGateway.Id
  $natGateway | Select-Object Name, `
    @{N='OutboundIPs';E={$_.PublicIpAddresses.Count}}, `
    @{N='IdleTimeout';E={$_.IdleTimeoutInMinutes}}
}
```

### Remediation

| Issue | Fix |
|---|---|
| NSG denies outbound traffic | Add rule: `Allow TCP 443 to 0.0.0.0/0 (HTTPS)` or `Allow TCP 80 to 0.0.0.0/0 (HTTP)` |
| Route table sends traffic to wrong hop | Update UDR: Change `0.0.0.0/0` destination to correct firewall NIC IP |
| Azure Firewall blocks by default | Add network rule or application rule allowing destination |
| NAT Gateway not configured | Associate NAT Gateway to subnet for deterministic outbound IPs |

---

## Scenario 2: VMs in Different Subnets Cannot Communicate

### Symptoms

- Ping between subnets fails
- Application connection timeout between tiers (app → database)
- DNS resolution works, but TCP connections fail

### Diagnostic Steps

#### Step 1: Verify Subnet Configuration

```powershell
# Get both subnets
$appSubnet = Get-AzVirtualNetworkSubnetConfig -Name "AppSubnet" `
  -VirtualNetwork (Get-AzVirtualNetwork -Name "vnet-prod" -ResourceGroupName "rg-prod")

$dbSubnet = Get-AzVirtualNetworkSubnetConfig -Name "DataSubnet" `
  -VirtualNetwork (Get-AzVirtualNetwork -Name "vnet-prod" -ResourceGroupName "rg-prod")

# Check IP ranges
@($appSubnet, $dbSubnet) | Select-Object Name, AddressPrefix
```

#### Step 2: Check NSG Rules on Both Subnets

```powershell
# Get NSGs for each subnet
$appNSG = Get-AzNetworkSecurityGroup -Name "nsg-app" -ResourceGroupName "rg-prod"
$dataNSG = Get-AzNetworkSecurityGroup -Name "nsg-data" -ResourceGroupName "rg-prod"

# Check inbound rules on data subnet (must allow from app subnet)
Write-Host "=== Data Subnet Inbound Rules ==="
$dataNSG.SecurityRules | Where-Object { $_.Direction -eq "Inbound" } | 
  Select-Object Name, Protocol, SourceAddressPrefix, DestinationPortRange, Access | 
  Format-Table

# Look for rules that allow source = app subnet (10.1.0.0/24) and port = 3306 (MySQL), 5432 (PostgreSQL), 1433 (SQL)
```

#### Step 3: Test Network Connectivity

```powershell
# From app VM, test connectivity to database VM
$appVM = Get-AzVM -Name "vm-app-01" -ResourceGroupName "rg-prod"
$appNIC = Get-AzNetworkInterface -ResourceId ($appVM.NetworkProfile.NetworkInterfaces[0].Id)
$appPrivateIP = $appNIC.IpConfigurations[0].PrivateIpAddress

# From database VM, check if inbound is allowed
# (Run this via SSH/RDP on the database VM)
# Linux: `sudo tcpdump -i eth0 -nn 'host <app-vm-ip>'`
# Windows: `netstat -an | findstr <port>`
```

#### Step 4: Check Route Tables

```powershell
# Verify both subnets are in the same VNet and have matching routing
$routeApp = Get-AzRouteTable -Name "rt-app" -ResourceGroupName "rg-prod" -ErrorAction SilentlyContinue
$routeData = Get-AzRouteTable -Name "rt-data" -ResourceGroupName "rg-prod" -ErrorAction SilentlyContinue

if ($routeApp) {
  Write-Host "=== App Subnet Routes ==="
  $routeApp.Routes | Select-Object Name, AddressPrefix, NextHopType | Format-Table
}

if ($routeData) {
  Write-Host "=== Data Subnet Routes ==="
  $routeData.Routes | Select-Object Name, AddressPrefix, NextHopType | Format-Table
}
```

### Remediation

| Issue | Fix |
|---|---|
| NSG on data subnet blocks inbound | Add inbound rule: Allow TCP port 3306/5432/1433 from app subnet |
| Route table sends traffic to wrong interface | Verify local routes include both subnets (via local gateway) |
| Traffic routed through firewall | If firewall between subnets, allow both directions in firewall rules |

---

## Scenario 3: Cannot Reach Peered VNet

### Symptoms

- Cross-VNet ping fails
- Applications in peered VNets timeout when connecting
- VNet peering shows "Connected" but traffic doesn't flow

### Diagnostic Steps

#### Step 1: Check Peering Status

```powershell
# Get peering relationship
$sourceVNet = Get-AzVirtualNetwork -Name "vnet-spoke-01" -ResourceGroupName "rg-prod"
$peering = Get-AzVirtualNetworkPeering -VirtualNetworkName $sourceVNet.Name `
  -ResourceGroupName $sourceVNet.ResourceGroupName

$peering | Select-Object Name, `
  @{N='PeeringState';E={$_.PeeringState}}, `
  @{N='AllowVirtualNetworkAccess';E={$_.AllowVirtualNetworkAccess}}, `
  @{N='AllowForwardedTraffic';E={$_.AllowForwardedTraffic}}, `
  @{N='AllowGatewayTransit';E={$_.AllowGatewayTransit}} | Format-Table
```

#### Step 2: Verify Peering Configuration

```powershell
# Both directions must be configured correctly
# Spoke → Hub
$hubPeering = Get-AzVirtualNetworkPeering -VirtualNetworkName "vnet-hub" `
  -ResourceGroupName "rg-hub" -Name "peering-hub-to-spoke-01"

# Must be set to true for traffic to flow
Write-Host "AllowVirtualNetworkAccess: $($hubPeering.AllowVirtualNetworkAccess)"
Write-Host "AllowForwardedTraffic: $($hubPeering.AllowForwardedTraffic)"
```

#### Step 3: Check Route Tables in Peered VNets

```powershell
# If UDRs exist, they might block peered traffic
$spoke1Routes = Get-AzRouteTable -Name "rt-spoke-01" -ResourceGroupName "rg-prod"
$spoke1Routes.Routes | Where-Object { $_.AddressPrefix -match "10.0" } | Format-Table

# Check if next hop is set to firewall (if yes, firewall must allow cross-peering traffic)
```

#### Step 4: Check Network Security Groups

```powershell
# NSGs in both VNets must allow bidirectional traffic
# Source VNet NSG
$sourceNSG = Get-AzNetworkSecurityGroup -Name "nsg-spoke-01" -ResourceGroupName "rg-prod"
$sourceNSG.SecurityRules | Where-Object { $_.Direction -eq "Outbound" } | 
  Select-Object Name, DestinationAddressPrefix, Access | Format-Table

# Destination VNet NSG
$destNSG = Get-AzNetworkSecurityGroup -Name "nsg-hub" -ResourceGroupName "rg-hub"
$destNSG.SecurityRules | Where-Object { $_.Direction -eq "Inbound" } | 
  Select-Object Name, SourceAddressPrefix, Access | Format-Table
```

### Remediation

| Issue | Fix |
|---|---|
| Peering state is "Initiated" (not connected) | Delete and recreate peering; both sides must have matching config |
| AllowVirtualNetworkAccess is false | Update: `Update-AzVirtualNetworkPeering -AllowVirtualNetworkAccess $true` |
| NSG blocks peered traffic | Add allow rules for source/destination CIDR ranges |
| Firewall blocks peered traffic | Add network/app rules allowing peered VNet CIDR ranges |

---

## Scenario 4: Hybrid Connectivity (VPN/ExpressRoute) Down

### Symptoms

- Cannot reach on-premises resources from Azure
- Site-to-site VPN connection shows "Disconnected"
- BGP neighbor status is "Down"

### Diagnostic Steps

#### Step 1: Check VPN Gateway Status

```powershell
# Check gateway connection status
$vpnGateway = Get-AzVirtualNetworkGateway -Name "vgw-prod" -ResourceGroupName "rg-hub"
$connections = Get-AzVirtualNetworkGatewayConnection -ResourceGroupName "rg-hub" `
  -Filter { $_.VirtualNetworkGateway1 -eq $vpnGateway }

$connections | Select-Object Name, ConnectionStatus, ConnectionType, `
  @{N='BGPStatus';E={$_.BgpSettings.BgpPeeringStatus}} | Format-Table
```

#### Step 2: Check VPN Connection Details

```powershell
# Get detailed connection information
$connection = Get-AzVirtualNetworkGatewayConnection -Name "connection-to-onprem" `
  -ResourceGroupName "rg-hub"

Write-Host "Connection Status: $($connection.ConnectionStatus)"
Write-Host "Ingress Bytes: $($connection.EgressBytesTransferred)"
Write-Host "Egress Bytes: $($connection.IngressBytesTransferred)"

# If bytes not increasing, tunnel might be stuck
```

#### Step 3: Check BGP Peering

```powershell
# If using BGP (dynamic routing)
$vpnGateway = Get-AzVirtualNetworkGateway -Name "vgw-prod" -ResourceGroupName "rg-hub"
Write-Host "BGP Enabled: $($vpnGateway.BgpSettings.BgpPeeringAddresses)"

# Check peer BGP AS number on on-prem device
Write-Host "On-Prem BGP AS: (check your VPN appliance config)"
```

#### Step 4: Verify IPsec Parameters

```powershell
# Check if IPsec parameters match between Azure and on-prem
$connection = Get-AzVirtualNetworkGatewayConnection -Name "connection-to-onprem" `
  -ResourceGroupName "rg-hub"

Write-Host "IKE Version: $($connection.AuthenticationMethod)"
Write-Host "Encryption: Check Azure Portal → Connections → Configuration"

# Common issues:
# - IKE version mismatch (IKEv1 vs IKEv2)
# - Encryption algorithm mismatch
# - Firewall blocking UDP 500/4500 (IPsec)
```

### Remediation

| Issue | Fix |
|---|---|
| Connection is "Disconnected" | 1. Check on-prem VPN appliance logs; 2. Verify pre-shared key matches; 3. Restart connection: `Reset-AzVirtualNetworkGatewayConnection -Name connection-to-onprem` |
| BGP status is "Down" | 1. Check on-prem BGP config; 2. Verify BGP AS numbers match; 3. Check firewall allows BGP (TCP 179) |
| High latency or packet loss | 1. Check VPN gateway SKU (higher SKU = better performance); 2. Check on-prem internet connection quality; 3. Consider ExpressRoute for consistent performance |
| IPsec negotiation fails | 1. Match IKE version; 2. Match encryption (AES-256/256); 3. Verify firewall allows UDP 500/4500 |

---

## Useful Commands Reference

### Quick Network Diagnostics

```powershell
# Test connectivity from Azure VM (run via Bastion or RDP)
Test-NetConnection -ComputerName "<on-prem-ip>" -Port 3306  # Database port

# Check routing table on VM
route print  # Windows
ip route     # Linux

# Check open ports
netstat -tuln | grep LISTEN  # Linux
netstat -an | findstr LISTENING  # Windows
```

### Troubleshooting with Azure Network Watcher

```powershell
# Enable flow logs (if not already enabled)
$nsg = Get-AzNetworkSecurityGroup -Name "nsg-app" -ResourceGroupName "rg-prod"
Set-AzNetworkWatcherFlowLog -NetworkSecurityGroupId $nsg.Id `
  -TargetResourceId (Get-AzStorageAccount -Name "stgtroubleshoot" -ResourceGroupName "rg-prod").Id `
  -Enabled $true

# Check IP flow verify (test if traffic would be allowed)
Get-AzNetworkWatcherNextHop -ResourceGroupName "rg-prod" `
  -NetworkWatcherName "NetworkWatcher_eastus" `
  -TargetVirtualMachineId "<vm-id>" `
  -SourceIPAddress "10.1.0.4" `
  -DestinationIPAddress "10.2.0.4"
```

---

## Escalation Path

| Issue Severity | Action | Escalate To |
|---|---|---|
| Single service unreachable | Review NSG rules, test connectivity | Network Team |
| Multiple services down | Check firewall, BGP status | Platform Operations |
| Regional connectivity lost | Check VPN gateway, circuit status | Infrastructure Lead |
| Suspected DDoS or attack | Check Azure Security Center, block IPs | Security Team |

---

## Prevention

1. **Monitor daily**: Set up alerts on VPN connection status, firewall rule changes
2. **Test monthly**: Run failover drills between primary and backup connectivity
3. **Document thoroughly**: Keep current network diagrams and firewall rule justifications
4. **Use Network Watcher**: Enable flow logs for troubleshooting retroactively
5. **Automate**: Script common checks (peering status, route tables) and alert on changes
