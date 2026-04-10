variable "location" {
  description = "Azure region"
  type        = string
  default     = "switzerlandnorth"
}

variable "resource_group_name" {
  description = "Resource group name"
  type        = string
  default     = "Bi_solution_rg"
}

variable "ssh_public_key" {
  description = "SSH public key"
  type        = string
}

variable "hub_address_space" {
  description = "Hub VNet address space"
  type        = string
  default     = "10.10.0.0/24"   # ← fixed from /16 to /24
}

variable "vnet1_address_space" {
  description = "Vnet1 address space"
  type        = string
  default     = "10.10.1.0/24"
}

variable "vnet2_address_space" {
  description = "Vnet2 address space"
  type        = string
  default     = "10.10.2.0/24"
}

variable "vnet3_address_space" {
  description = "Vnet3 address space"
  type        = string
  default     = "10.10.3.0/24"
}

variable "kali_ip" {
  description = "KaliLinux public IP for attack simulation"
  type        = string
  default     = "196.117.56.86"  
}

variable "sql_admin_password" {
  description = "SQL Server admin password"
  type        = string
  sensitive   = true
}

variable "allowed_ip" {
  description = "Your IP for SQL firewall"
  type        = string
}

variable "alert_email" {
  description = "Email to receive security alerts"
  type        = string
}

variable "subscription_id" {
  type = string
}

variable "nsg_name" {
  type = string
}

variable "vpn_root_certificate" {
  description = "Base64 root certificate for VPN"
  type        = string
}

variable "sentinel_principal_id" {
  description = "Sentinel service principal ID"
  type        = string
}