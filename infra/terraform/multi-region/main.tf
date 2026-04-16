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

resource "azurerm_resource_group" "primary" {
  name     = var.primary_resource_group_name
  location = var.primary_location
}

resource "azurerm_resource_group" "secondary" {
  name     = var.secondary_resource_group_name
  location = var.secondary_location
}

resource "azurerm_virtual_network" "primary_hub" {
  name                = "${var.name_prefix}-primary-hub-vnet"
  location            = azurerm_resource_group.primary.location
  resource_group_name = azurerm_resource_group.primary.name
  address_space       = [var.primary_hub_cidr]
}

resource "azurerm_subnet" "primary_gateway" {
  name                 = "GatewaySubnet"
  resource_group_name  = azurerm_resource_group.primary.name
  virtual_network_name = azurerm_virtual_network.primary_hub.name
  address_prefixes     = ["10.10.0.0/24"]
}

resource "azurerm_virtual_network" "secondary_hub" {
  name                = "${var.name_prefix}-secondary-hub-vnet"
  location            = azurerm_resource_group.secondary.location
  resource_group_name = azurerm_resource_group.secondary.name
  address_space       = [var.secondary_hub_cidr]
}

resource "azurerm_subnet" "secondary_gateway" {
  name                 = "GatewaySubnet"
  resource_group_name  = azurerm_resource_group.secondary.name
  virtual_network_name = azurerm_virtual_network.secondary_hub.name
  address_prefixes     = ["10.20.0.0/24"]
}

resource "azurerm_virtual_network_peering" "primary_to_secondary" {
  name                      = "primary-to-secondary"
  resource_group_name       = azurerm_resource_group.primary.name
  virtual_network_name      = azurerm_virtual_network.primary_hub.name
  remote_virtual_network_id = azurerm_virtual_network.secondary_hub.id
  allow_virtual_network_access = true
  allow_forwarded_traffic      = true
}

resource "azurerm_virtual_network_peering" "secondary_to_primary" {
  name                      = "secondary-to-primary"
  resource_group_name       = azurerm_resource_group.secondary.name
  virtual_network_name      = azurerm_virtual_network.secondary_hub.name
  remote_virtual_network_id = azurerm_virtual_network.primary_hub.id
  allow_virtual_network_access = true
  allow_forwarded_traffic      = true
}

resource "azurerm_traffic_manager_profile" "global" {
  count               = var.enable_traffic_manager ? 1 : 0
  name                = "${var.name_prefix}-global-tm"
  resource_group_name = azurerm_resource_group.primary.name

  traffic_routing_method = "Priority"

  dns_config {
    relative_name = "${var.name_prefix}-global-routing"
    ttl           = 30
  }

  monitor_config {
    protocol                     = "HTTPS"
    port                         = 443
    path                         = "/health"
    interval_in_seconds          = 30
    timeout_in_seconds           = 10
    tolerated_number_of_failures = 3
  }
}

resource "azurerm_traffic_manager_external_endpoint" "primary_endpoint" {
  count               = var.enable_traffic_manager ? 1 : 0
  name                = "primary-endpoint"
  profile_id          = azurerm_traffic_manager_profile.global[0].id
  target              = var.primary_endpoint_dns
  endpoint_location   = var.primary_location
  priority            = 1
  weight              = 100
}

resource "azurerm_traffic_manager_external_endpoint" "secondary_endpoint" {
  count               = var.enable_traffic_manager ? 1 : 0
  name                = "secondary-endpoint"
  profile_id          = azurerm_traffic_manager_profile.global[0].id
  target              = var.secondary_endpoint_dns
  endpoint_location   = var.secondary_location
  priority            = 2
  weight              = 100
}
