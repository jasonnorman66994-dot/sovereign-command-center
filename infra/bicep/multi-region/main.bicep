targetScope = 'resourceGroup'

@description('Primary Azure region.')
param primaryLocation string = resourceGroup().location

@description('Secondary Azure region for disaster recovery.')
param secondaryLocation string = 'westus2'

@description('Prefix applied to all resource names.')
param namePrefix string = 'scc'

@description('Primary hub CIDR.')
param primaryHubCidr string = '10.10.0.0/16'

@description('Secondary hub CIDR.')
param secondaryHubCidr string = '10.20.0.0/16'

@description('Deploy Traffic Manager profile for global failover.')
param enableTrafficManager bool = true

var primaryHubVnetName = '${namePrefix}-primary-hub-vnet'
var secondaryHubVnetName = '${namePrefix}-secondary-hub-vnet'

resource primaryHubVnet 'Microsoft.Network/virtualNetworks@2023-11-01' = {
  name: primaryHubVnetName
  location: primaryLocation
  properties: {
    addressSpace: {
      addressPrefixes: [primaryHubCidr]
    }
    subnets: [
      {
        name: 'GatewaySubnet'
        properties: {
          addressPrefix: '10.10.0.0/24'
        }
      }
      {
        name: 'SharedServicesSubnet'
        properties: {
          addressPrefix: '10.10.1.0/24'
        }
      }
    ]
  }
}

resource secondaryHubVnet 'Microsoft.Network/virtualNetworks@2023-11-01' = {
  name: secondaryHubVnetName
  location: secondaryLocation
  properties: {
    addressSpace: {
      addressPrefixes: [secondaryHubCidr]
    }
    subnets: [
      {
        name: 'GatewaySubnet'
        properties: {
          addressPrefix: '10.20.0.0/24'
        }
      }
      {
        name: 'SharedServicesSubnet'
        properties: {
          addressPrefix: '10.20.1.0/24'
        }
      }
    ]
  }
}

resource primaryToSecondaryPeering 'Microsoft.Network/virtualNetworks/virtualNetworkPeerings@2023-11-01' = {
  name: '${primaryHubVnet.name}/primary-to-secondary'
  properties: {
    allowVirtualNetworkAccess: true
    allowForwardedTraffic: true
    remoteVirtualNetwork: {
      id: secondaryHubVnet.id
    }
  }
}

resource secondaryToPrimaryPeering 'Microsoft.Network/virtualNetworks/virtualNetworkPeerings@2023-11-01' = {
  name: '${secondaryHubVnet.name}/secondary-to-primary'
  properties: {
    allowVirtualNetworkAccess: true
    allowForwardedTraffic: true
    remoteVirtualNetwork: {
      id: primaryHubVnet.id
    }
  }
}

resource trafficManagerProfile 'Microsoft.Network/trafficManagerProfiles@2022-04-01' = if (enableTrafficManager) {
  name: '${namePrefix}-global-tm'
  location: 'global'
  properties: {
    profileStatus: 'Enabled'
    trafficRoutingMethod: 'Priority'
    dnsConfig: {
      relativeName: '${namePrefix}-global-routing'
      ttl: 30
    }
    monitorConfig: {
      protocol: 'HTTPS'
      port: 443
      path: '/health'
      intervalInSeconds: 30
      timeoutInSeconds: 10
      toleratedNumberOfFailures: 3
    }
  }
}

output primaryHubVnetId string = primaryHubVnet.id
output secondaryHubVnetId string = secondaryHubVnet.id
output trafficManagerFqdn string = enableTrafficManager ? trafficManagerProfile.properties.dnsConfig.fqdn : 'disabled'
