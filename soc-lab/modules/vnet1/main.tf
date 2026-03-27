variable "resource_group_name" {}
variable "location" {}

resource "azurerm_virtual_network" "vnet1" {
  name                = "Vnet1"
  address_space       = ["10.10.1.0/24"]
  location            = var.location
  resource_group_name = var.resource_group_name
}

resource "azurerm_subnet" "dmz" {
  name                 = "DMZ-Subnet"
  resource_group_name  = var.resource_group_name
  virtual_network_name = azurerm_virtual_network.vnet1.name
  address_prefixes     = ["10.10.1.0/27"]
  service_endpoints    = ["Microsoft.Storage"]
}

resource "azurerm_subnet" "vm_ad" {
  name                 = "vm_AD-Subnet"
  resource_group_name  = var.resource_group_name
  virtual_network_name = azurerm_virtual_network.vnet1.name
  address_prefixes     = ["10.10.1.32/27"]
}

resource "azurerm_subnet" "firewall" {
  name                 = "AzureFirewallSubnet"
  resource_group_name  = var.resource_group_name
  virtual_network_name = azurerm_virtual_network.vnet1.name
  address_prefixes     = ["10.10.1.64/26"]
}

output "vnet1_id" {
  value = azurerm_virtual_network.vnet1.id
}

output "dmz_subnet_id" {
  value = azurerm_subnet.dmz.id
}

output "vm_ad_subnet_id" {
  value = azurerm_subnet.vm_ad.id
}

output "vnet1_name" {
  value = azurerm_virtual_network.vnet1.name
}

