# # modules/vpn/main.tf

# variable "resource_group_name" {}
# variable "location" {}
# variable "gateway_subnet_id" {}

# # Public IP for VPN Gateway
# resource "azurerm_public_ip" "vpn_pip" {
#   name                = "VPN-Gateway-PIP"
#   location            = var.location
#   resource_group_name = var.resource_group_name
#   allocation_method   = "Static"
#   sku                 = "Standard"
#   zones               = ["1", "2", "3"]
# }

# # VPN Gateway
# resource "azurerm_virtual_network_gateway" "vpn_gateway" {
#   name                = "AITDR-VPN-Gateway"
#   location            = var.location
#   resource_group_name = var.resource_group_name
#   type                = "Vpn"
#   vpn_type            = "RouteBased"
#   sku                 = "VpnGw1AZ"   
#   active_active       = false

#   ip_configuration {
#     name                          = "vpn-ip-config"
#     public_ip_address_id          = azurerm_public_ip.vpn_pip.id
#     private_ip_address_allocation = "Dynamic"
#     subnet_id                     = var.gateway_subnet_id
#   }

#   vpn_client_configuration {
#     address_space = ["172.16.0.0/24"]
#     vpn_client_protocols = ["IkeV2"]

#     root_certificate {
#       name             = "AITDR-Root-Cert"
#       public_cert_data = var.vpn_root_certificate
#     }
#   }
# }

# variable "vpn_root_certificate" {
#   description = "Base64 encoded root certificate"
#   type        = string
# }

# output "vpn_gateway_ip" {
#   value = azurerm_public_ip.vpn_pip.ip_address
# }