terraform {
  required_version = ">= 1.6.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.108"
    }
  }
}

provider "azurerm" {
  features {}
}

resource "azurerm_resource_group" "this" {
  name     = var.resource_group_name
  location = var.location
}

resource "azurerm_virtual_network" "hub" {
  name                = "${var.name_prefix}-hub-vnet"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  address_space       = [var.hub_cidr]
}

resource "azurerm_subnet" "hub_firewall" {
  name                 = "AzureFirewallSubnet"
  resource_group_name  = azurerm_resource_group.this.name
  virtual_network_name = azurerm_virtual_network.hub.name
  address_prefixes     = ["10.0.1.0/24"]
}

resource "azurerm_subnet" "hub_gateway" {
  name                 = "GatewaySubnet"
  resource_group_name  = azurerm_resource_group.this.name
  virtual_network_name = azurerm_virtual_network.hub.name
  address_prefixes     = ["10.0.0.0/24"]
}

resource "azurerm_virtual_network" "spokes" {
  for_each            = var.spoke_cidrs
  name                = "${var.name_prefix}-${each.key}-vnet"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  address_space       = [each.value]
}

resource "azurerm_subnet" "spoke_app" {
  for_each             = azurerm_virtual_network.spokes
  name                 = "ApplicationSubnet"
  resource_group_name  = azurerm_resource_group.this.name
  virtual_network_name = each.value.name
  address_prefixes     = [cidrsubnet(each.value.address_space[0], 8, 1)]
}

resource "azurerm_subnet" "spoke_data" {
  for_each             = azurerm_virtual_network.spokes
  name                 = "DataSubnet"
  resource_group_name  = azurerm_resource_group.this.name
  virtual_network_name = each.value.name
  address_prefixes     = [cidrsubnet(each.value.address_space[0], 8, 2)]
}

resource "azurerm_virtual_network_peering" "hub_to_spoke" {
  for_each                  = azurerm_virtual_network.spokes
  name                      = "hub-to-${each.key}"
  resource_group_name       = azurerm_resource_group.this.name
  virtual_network_name      = azurerm_virtual_network.hub.name
  remote_virtual_network_id = each.value.id
  allow_virtual_network_access = true
  allow_forwarded_traffic      = true
}

resource "azurerm_virtual_network_peering" "spoke_to_hub" {
  for_each                  = azurerm_virtual_network.spokes
  name                      = "${each.key}-to-hub"
  resource_group_name       = azurerm_resource_group.this.name
  virtual_network_name      = each.value.name
  remote_virtual_network_id = azurerm_virtual_network.hub.id
  allow_virtual_network_access = true
  allow_forwarded_traffic      = true
  use_remote_gateways          = true
}

resource "azurerm_public_ip" "firewall" {
  count               = var.enable_firewall ? 1 : 0
  name                = "${var.name_prefix}-hub-fw-pip"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  allocation_method   = "Static"
  sku                 = "Standard"
}

resource "azurerm_firewall_policy" "this" {
  count               = var.enable_firewall ? 1 : 0
  name                = "${var.name_prefix}-hub-fw-policy"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  sku                 = "Standard"
}

resource "azurerm_firewall" "this" {
  count               = var.enable_firewall ? 1 : 0
  name                = "${var.name_prefix}-hub-fw"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  sku_name            = "AZFW_VNet"
  sku_tier            = "Standard"
  firewall_policy_id  = azurerm_firewall_policy.this[0].id

  ip_configuration {
    name                 = "configuration"
    subnet_id            = azurerm_subnet.hub_firewall.id
    public_ip_address_id = azurerm_public_ip.firewall[0].id
  }
}

resource "azurerm_route_table" "spokes" {
  count               = var.enable_firewall ? 1 : 0
  name                = "${var.name_prefix}-spoke-rt"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name

  route {
    name                   = "default-via-firewall"
    address_prefix         = "0.0.0.0/0"
    next_hop_type          = "VirtualAppliance"
    next_hop_in_ip_address = azurerm_firewall.this[0].ip_configuration[0].private_ip_address
  }
}

resource "azurerm_subnet_route_table_association" "spoke_app" {
  for_each       = var.enable_firewall ? azurerm_subnet.spoke_app : {}
  subnet_id      = each.value.id
  route_table_id = azurerm_route_table.spokes[0].id
}
