variable "resource_group_name" {
  description = "Resource group name for hub-spoke deployment."
  type        = string
  default     = "rg-scc-hub-spoke"
}

variable "location" {
  description = "Azure region for resources."
  type        = string
  default     = "eastus"
}

variable "name_prefix" {
  description = "Name prefix for resources."
  type        = string
  default     = "scc"
}

variable "hub_cidr" {
  description = "Hub VNet CIDR."
  type        = string
  default     = "10.0.0.0/16"
}

variable "spoke_cidrs" {
  description = "Map of spoke name to CIDR block."
  type        = map(string)
  default = {
    spoke1 = "10.1.0.0/16"
    spoke2 = "10.2.0.0/16"
  }
}

variable "enable_firewall" {
  description = "Whether to deploy Azure Firewall and spoke default route table."
  type        = bool
  default     = true
}
