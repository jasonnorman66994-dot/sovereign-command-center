variable "name_prefix" {
  description = "Name prefix used across resources."
  type        = string
  default     = "scc"
}

variable "primary_resource_group_name" {
  description = "Primary region resource group name."
  type        = string
  default     = "rg-scc-primary"
}

variable "secondary_resource_group_name" {
  description = "Secondary region resource group name."
  type        = string
  default     = "rg-scc-secondary"
}

variable "primary_location" {
  description = "Primary Azure region."
  type        = string
  default     = "eastus"
}

variable "secondary_location" {
  description = "Secondary Azure region."
  type        = string
  default     = "westus2"
}

variable "primary_hub_cidr" {
  description = "Primary hub VNet CIDR."
  type        = string
  default     = "10.10.0.0/16"
}

variable "secondary_hub_cidr" {
  description = "Secondary hub VNet CIDR."
  type        = string
  default     = "10.20.0.0/16"
}

variable "enable_traffic_manager" {
  description = "Deploy Traffic Manager profile for global failover."
  type        = bool
  default     = true
}

variable "primary_endpoint_dns" {
  description = "DNS name for primary endpoint front door/app gateway public endpoint."
  type        = string
  default     = "primary.example.com"
}

variable "secondary_endpoint_dns" {
  description = "DNS name for secondary endpoint front door/app gateway public endpoint."
  type        = string
  default     = "secondary.example.com"
}
