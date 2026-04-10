# ============================================
# MODULE: NSGs - All Subnets
# ============================================

variable "resource_group_name" {}
variable "location" {}
variable "kali_ip" {}
variable "dmz_subnet_id" {}
variable "vm_ad_subnet_id" {}
variable "data_subnet_id" {}
variable "siem_subnet_id" {}
variable "soar_subnet_id" {}

# ============================================
# NSG 1 - DMZ (Web Server)
# ============================================
resource "azurerm_network_security_group" "nsg_dmz" {
  name                = "NSG-DMZ"
  location            = var.location
  resource_group_name = var.resource_group_name

  # Allow KaliLinux to attack freely
  security_rule {
    name                       = "Allow-Kali-All"
    priority                   = 105
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "${var.kali_ip}/32"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "Allow-HTTP"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "80"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "Allow-HTTPS"
    priority                   = 120
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "Allow-SSH"
    priority                   = 130
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "${var.kali_ip}/32"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "Deny-All"
    priority                   = 4096
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

# ============================================
# NSG 2 - vm_AD SUBNET (Active Directory)
# Only accessible from internal VNets
# ============================================
resource "azurerm_network_security_group" "nsg_ad" {
  name                = "NSG-AD"
  location            = var.location
  resource_group_name = var.resource_group_name

  # Allow traffic from Vnet1 only
  security_rule {
    name                       = "Allow-Internal-Vnet1"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "10.10.1.0/24"
    destination_address_prefix = "*"
  }

  # Allow RDP for management
  security_rule {
    name                       = "Allow-RDP"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3389"
    source_address_prefix      = "${var.kali_ip}/32"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "Deny-All"
    priority                   = 4096
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

# ============================================
# NSG 3 - DATA SUBNET (MySQL + SQL)
# Only port 3306 from Vnet1
# ============================================
resource "azurerm_network_security_group" "nsg_data" {
  name                = "NSG-Data"
  location            = var.location
  resource_group_name = var.resource_group_name

  security_rule {
    name                       = "Allow-MySQL-From-Vnet1"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3306"
    source_address_prefix      = "10.10.1.0/24"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "Allow-SQL-From-Vnet1"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "1433"
    source_address_prefix      = "10.10.1.0/24"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "Deny-All"
    priority                   = 4096
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

# ============================================
# NSG 4 - SIEM SUBNET (Microsoft Sentinel)
# Accepts logs from ALL VNets
# ============================================
resource "azurerm_network_security_group" "nsg_siem" {
  name                = "NSG-SIEM"
  location            = var.location
  resource_group_name = var.resource_group_name

  # Accept logs from all VNets
  security_rule {
    name                       = "Allow-Logs-All-Vnets"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "10.10.0.0/16"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "Deny-Internet"
    priority                   = 4096
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "Internet"
    destination_address_prefix = "*"
  }
}

# ============================================
# NSG 5 - SOAR SUBNET (Logic Apps)
# Only triggered by SIEM
# ============================================
resource "azurerm_network_security_group" "nsg_soar" {
  name                = "NSG-SOAR"
  location            = var.location
  resource_group_name = var.resource_group_name

  # Only SIEM subnet can trigger SOAR
  security_rule {
    name                       = "Allow-From-SIEM"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "10.10.3.0/27"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "Deny-All"
    priority                   = 4096
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}


output "nsg_dmz_id" {
  value = azurerm_network_security_group.nsg_dmz.id
 }

# ============================================
# ASSOCIATE NSGs TO SUBNETS
# ============================================
resource "azurerm_subnet_network_security_group_association" "dmz" {
  subnet_id                 = var.dmz_subnet_id
  network_security_group_id = azurerm_network_security_group.nsg_dmz.id
}

resource "azurerm_subnet_network_security_group_association" "ad" {
  subnet_id                 = var.vm_ad_subnet_id
  network_security_group_id = azurerm_network_security_group.nsg_ad.id
}

resource "azurerm_subnet_network_security_group_association" "data" {
  subnet_id                 = var.data_subnet_id
  network_security_group_id = azurerm_network_security_group.nsg_data.id
}

resource "azurerm_subnet_network_security_group_association" "siem" {
  subnet_id                 = var.siem_subnet_id
  network_security_group_id = azurerm_network_security_group.nsg_siem.id
}

resource "azurerm_subnet_network_security_group_association" "soar" {
  subnet_id                 = var.soar_subnet_id
  network_security_group_id = azurerm_network_security_group.nsg_soar.id
}

output "nsg_soar_id" {
  value = azurerm_network_security_group.nsg_soar.id
}
