variable "resource_group_name" {}
variable "location" {}

resource "azurerm_virtual_network" "vnet3" {
  name                = "Vnet3"
  address_space       = ["10.10.3.0/24"]
  location            = var.location
  resource_group_name = var.resource_group_name
}

resource "azurerm_subnet" "siem" {
  name                 = "SIEM-Subnet"
  resource_group_name  = var.resource_group_name
  virtual_network_name = azurerm_virtual_network.vnet3.name
  address_prefixes     = ["10.10.3.0/27"]
}

resource "azurerm_subnet" "soar" {
  name                 = "SOAR-Subnet"
  resource_group_name  = var.resource_group_name
  virtual_network_name = azurerm_virtual_network.vnet3.name
  address_prefixes     = ["10.10.3.32/27"]
}

resource "azurerm_subnet" "datalake" {
  name                 = "DataLake-Subnet"
  resource_group_name  = var.resource_group_name
  virtual_network_name = azurerm_virtual_network.vnet3.name
  address_prefixes     = ["10.10.3.64/27"]
}

resource "azurerm_subnet" "gateway" {
  name                 = "GatewaySubnet"
  resource_group_name  = var.resource_group_name
  virtual_network_name = azurerm_virtual_network.vnet3.name
  address_prefixes     = ["10.10.3.96/27"]
}

output "vnet3_id" {
  value = azurerm_virtual_network.vnet3.id
}

output "siem_subnet_id" {
  value = azurerm_subnet.siem.id
}

output "vnet3_name" {
  value = azurerm_virtual_network.vnet3.name
}

output "soar_subnet_id" {
  value = azurerm_subnet.soar.id
}
