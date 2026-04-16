output "primary_hub_vnet_id" {
  description = "Resource ID of the primary hub VNet."
  value       = azurerm_virtual_network.primary_hub.id
}

output "secondary_hub_vnet_id" {
  description = "Resource ID of the secondary hub VNet."
  value       = azurerm_virtual_network.secondary_hub.id
}

output "traffic_manager_fqdn" {
  description = "Traffic Manager DNS name when enabled."
  value       = var.enable_traffic_manager ? azurerm_traffic_manager_profile.global[0].fqdn : null
}
