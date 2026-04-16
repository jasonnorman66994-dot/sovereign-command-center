output "hub_vnet_id" {
  description = "Resource ID of the hub VNet."
  value       = azurerm_virtual_network.hub.id
}

output "spoke_vnet_ids" {
  description = "Resource IDs of spoke VNets."
  value       = { for k, v in azurerm_virtual_network.spokes : k => v.id }
}

output "firewall_private_ip" {
  description = "Private IP of Azure Firewall when enabled."
  value       = var.enable_firewall ? azurerm_firewall.this[0].ip_configuration[0].private_ip_address : null
}
