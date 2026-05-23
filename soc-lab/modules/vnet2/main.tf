variable "resource_group_name" {}
variable "location" {}
variable "dmz_subnet_id" {}
variable "data_subnet_id" {}


resource "azurerm_virtual_network" "vnet2" {
  name                = "Vnet2"
  address_space       = ["10.10.2.0/24"]
  location            = var.location
  resource_group_name = var.resource_group_name
}

resource "azurerm_subnet" "data" {
  name                 = "Data-Subnet"
  resource_group_name  = var.resource_group_name
  virtual_network_name = azurerm_virtual_network.vnet2.name
  address_prefixes     = ["10.10.2.0/27"]
  service_endpoints    = ["Microsoft.Storage"]
}

resource "azurerm_subnet" "analytics" {
  name                 = "Analytics-Subnet"
  resource_group_name  = var.resource_group_name
  virtual_network_name = azurerm_virtual_network.vnet2.name
  address_prefixes     = ["10.10.2.32/27"]
}

resource "azurerm_subnet" "gateway" {
  name                 = "GatewaySubnet"
  resource_group_name  = var.resource_group_name
  virtual_network_name = azurerm_virtual_network.vnet2.name
  address_prefixes     = ["10.10.2.64/27"]
}

output "vnet2_id" {
  value = azurerm_virtual_network.vnet2.id
}

output "data_subnet_id" {
  value = azurerm_subnet.data.id
}

output "vnet2_name" {
  value = azurerm_virtual_network.vnet2.name
}

output "analytics_subnet_id" {
  value = azurerm_subnet.analytics.id
}

output "gateway_subnet_id" {
  value = azurerm_subnet.gateway.id
}

