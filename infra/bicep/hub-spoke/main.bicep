targetScope = 'resourceGroup'

@description('Primary Azure region for hub-spoke deployment.')
param location string = resourceGroup().location

@description('Prefix applied to all resource names.')
param namePrefix string = 'scc'

@description('Hub VNet CIDR block.')
param hubAddressPrefix string = '10.0.0.0/16'

@description('CIDR blocks for spoke VNets.')
param spokeAddressPrefixes array = [
  '10.1.0.0/16'
  '10.2.0.0/16'
]

@description('On-premises address ranges allowed through VPN/ER.')
param onPremAddressPrefixes array = [
  '172.16.0.0/16'
]

@description('Deploy Azure Firewall and route all spoke egress through it.')
param enableFirewall bool = true

var hubVnetName = '${namePrefix}-hub-vnet'
var firewallPipName = '${namePrefix}-hub-fw-pip'
var firewallPolicyName = '${namePrefix}-hub-fw-policy'
var firewallName = '${namePrefix}-hub-fw'
var routeTableName = '${namePrefix}-spoke-rt'

resource hubVnet 'Microsoft.Network/virtualNetworks@2023-11-01' = {
  name: hubVnetName
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: [hubAddressPrefix]
    }
    subnets: [
      {
        name: 'AzureFirewallSubnet'
        properties: {
          addressPrefix: '10.0.1.0/24'
        }
      }
      {
        name: 'GatewaySubnet'
        properties: {
          addressPrefix: '10.0.0.0/24'
        }
      }
      {
        name: 'SharedServicesSubnet'
        properties: {
          addressPrefix: '10.0.2.0/24'
        }
      }
    ]
  }
}

resource spokeVnets 'Microsoft.Network/virtualNetworks@2023-11-01' = [for (prefix, i) in spokeAddressPrefixes: {
  name: '${namePrefix}-spoke-${i + 1}-vnet'
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: [prefix]
    }
    subnets: [
      {
        name: 'ApplicationSubnet'
        properties: {
          addressPrefix: '10.${i + 1}.1.0/24'
          routeTable: enableFirewall ? {
            id: spokeRouteTable.id
          } : null
        }
      }
      {
        name: 'DataSubnet'
        properties: {
          addressPrefix: '10.${i + 1}.2.0/24'
        }
      }
    ]
  }
}]

resource hubToSpokePeerings 'Microsoft.Network/virtualNetworks/virtualNetworkPeerings@2023-11-01' = [for (prefix, i) in spokeAddressPrefixes: {
  name: '${hubVnet.name}/hub-to-spoke-${i + 1}'
  properties: {
    allowVirtualNetworkAccess: true
    allowForwardedTraffic: true
    remoteVirtualNetwork: {
      id: spokeVnets[i].id
    }
  }
}]

resource spokeToHubPeerings 'Microsoft.Network/virtualNetworks/virtualNetworkPeerings@2023-11-01' = [for (prefix, i) in spokeAddressPrefixes: {
  name: '${spokeVnets[i].name}/spoke-${i + 1}-to-hub'
  properties: {
    allowVirtualNetworkAccess: true
    allowForwardedTraffic: true
    useRemoteGateways: true
    remoteVirtualNetwork: {
      id: hubVnet.id
    }
  }
}]

resource firewallPip 'Microsoft.Network/publicIPAddresses@2023-11-01' = if (enableFirewall) {
  name: firewallPipName
  location: location
  sku: {
    name: 'Standard'
  }
  properties: {
    publicIPAddressVersion: 'IPv4'
    publicIPAllocationMethod: 'Static'
  }
}

resource firewallPolicy 'Microsoft.Network/firewallPolicies@2023-11-01' = if (enableFirewall) {
  name: firewallPolicyName
  location: location
  properties: {
    threatIntelMode: 'Alert'
  }
}

resource firewall 'Microsoft.Network/azureFirewalls@2023-11-01' = if (enableFirewall) {
  name: firewallName
  location: location
  properties: {
    firewallPolicy: {
      id: firewallPolicy.id
    }
    sku: {
      name: 'AZFW_VNet'
      tier: 'Standard'
    }
    ipConfigurations: [
      {
        name: 'configuration'
        properties: {
          subnet: {
            id: '${hubVnet.id}/subnets/AzureFirewallSubnet'
          }
          publicIPAddress: {
            id: firewallPip.id
          }
        }
      }
    ]
  }
}

resource spokeRouteTable 'Microsoft.Network/routeTables@2023-11-01' = if (enableFirewall) {
  name: routeTableName
  location: location
  properties: {
    routes: [
      {
        name: 'default-via-firewall'
        properties: {
          addressPrefix: '0.0.0.0/0'
          nextHopType: 'VirtualAppliance'
          nextHopIpAddress: reference(firewall.id, '2023-11-01').ipConfigurations[0].properties.privateIPAddress
        }
      }
    ]
  }
}

resource hubNsg 'Microsoft.Network/networkSecurityGroups@2023-11-01' = {
  name: '${namePrefix}-hub-nsg'
  location: location
  properties: {
    securityRules: [
      {
        name: 'allow-onprem-to-shared-services'
        properties: {
          protocol: '*'
          sourcePortRange: '*'
          destinationPortRange: '*'
          sourceAddressPrefixes: onPremAddressPrefixes
          destinationAddressPrefix: '10.0.2.0/24'
          access: 'Allow'
          priority: 100
          direction: 'Inbound'
        }
      }
    ]
  }
}

output hubVnetResourceId string = hubVnet.id
output spokeVnetResourceIds array = [for v in spokeVnets: v.id]
output firewallPrivateIp string = enableFirewall ? reference(firewall.id, '2023-11-01').ipConfigurations[0].properties.privateIPAddress : 'not-deployed'
