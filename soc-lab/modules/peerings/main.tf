# ============================================
# MODULE: VNET PEERINGS
# Connects all VNets together
# ============================================

variable "resource_group_name" {}
variable "hub_vnet_id" {}
variable "hub_vnet_name" {}
variable "vnet1_id" {}
variable "vnet1_name" {}
variable "vnet2_id" {}
variable "vnet2_name" {}
variable "vnet3_id" {}
variable "vnet3_name" {}

# Hub <-> Vnet1
resource "azurerm_virtual_network_peering" "hub_to_vnet1" {
  name                      = "Hub-to-Vnet1"
  resource_group_name       = var.resource_group_name
  virtual_network_name      = var.hub_vnet_name
  remote_virtual_network_id = var.vnet1_id
  allow_forwarded_traffic   = true
  allow_gateway_transit     = true
}

resource "azurerm_virtual_network_peering" "vnet1_to_hub" {
  name                      = "Vnet1-to-Hub"
  resource_group_name       = var.resource_group_name
  virtual_network_name      = var.vnet1_name
  remote_virtual_network_id = var.hub_vnet_id
  allow_forwarded_traffic   = true
  use_remote_gateways       = false
}

# Hub <-> Vnet2
resource "azurerm_virtual_network_peering" "hub_to_vnet2" {
  name                      = "Hub-to-Vnet2"
  resource_group_name       = var.resource_group_name
  virtual_network_name      = var.hub_vnet_name
  remote_virtual_network_id = var.vnet2_id
  allow_forwarded_traffic   = true
  allow_gateway_transit     = true
}

resource "azurerm_virtual_network_peering" "vnet2_to_hub" {
  name                      = "Vnet2-to-Hub"
  resource_group_name       = var.resource_group_name
  virtual_network_name      = var.vnet2_name
  remote_virtual_network_id = var.hub_vnet_id
  allow_forwarded_traffic   = true
  use_remote_gateways       = false
}

# Hub <-> Vnet3
resource "azurerm_virtual_network_peering" "hub_to_vnet3" {
  name                      = "Hub-to-Vnet3"
  resource_group_name       = var.resource_group_name
  virtual_network_name      = var.hub_vnet_name
  remote_virtual_network_id = var.vnet3_id
  allow_forwarded_traffic   = true
  allow_gateway_transit     = true
}

resource "azurerm_virtual_network_peering" "vnet3_to_hub" {
  name                      = "Vnet3-to-Hub"
  resource_group_name       = var.resource_group_name
  virtual_network_name      = var.vnet3_name
  remote_virtual_network_id = var.hub_vnet_id
  allow_forwarded_traffic   = true
  use_remote_gateways       = false
}

# Vnet1 <-> Vnet2
resource "azurerm_virtual_network_peering" "vnet1_to_vnet2" {
  name                      = "Vnet1-to-Vnet2"
  resource_group_name       = var.resource_group_name
  virtual_network_name      = var.vnet1_name
  remote_virtual_network_id = var.vnet2_id
  allow_forwarded_traffic   = true
}

resource "azurerm_virtual_network_peering" "vnet2_to_vnet1" {
  name                      = "Vnet2-to-Vnet1"
  resource_group_name       = var.resource_group_name
  virtual_network_name      = var.vnet2_name
  remote_virtual_network_id = var.vnet1_id
  allow_forwarded_traffic   = true
}

# Vnet1 <-> Vnet3
resource "azurerm_virtual_network_peering" "vnet1_to_vnet3" {
  name                      = "Vnet1-to-Vnet3"
  resource_group_name       = var.resource_group_name
  virtual_network_name      = var.vnet1_name
  remote_virtual_network_id = var.vnet3_id
  allow_forwarded_traffic   = true
}

resource "azurerm_virtual_network_peering" "vnet3_to_vnet1" {
  name                      = "Vnet3-to-Vnet1"
  resource_group_name       = var.resource_group_name
  virtual_network_name      = var.vnet3_name
  remote_virtual_network_id = var.vnet1_id
  allow_forwarded_traffic   = true
}

# Vnet2 <-> Vnet3
resource "azurerm_virtual_network_peering" "vnet2_to_vnet3" {
  name                      = "Vnet2-to-Vnet3"
  resource_group_name       = var.resource_group_name
  virtual_network_name      = var.vnet2_name
  remote_virtual_network_id = var.vnet3_id
  allow_forwarded_traffic   = true
}

resource "azurerm_virtual_network_peering" "vnet3_to_vnet2" {
  name                      = "Vnet3-to-Vnet2"
  resource_group_name       = var.resource_group_name
  virtual_network_name      = var.vnet3_name
  remote_virtual_network_id = var.vnet2_id
  allow_forwarded_traffic   = true
}