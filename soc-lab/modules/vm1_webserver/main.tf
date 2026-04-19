# ============================================
# MODULE: VM1 WEB SERVER
# Secrets from Key Vault only
# Scripts externalized to files
# ============================================

variable "resource_group_name" {}
variable "location" {}
variable "key_vault_id" {}
variable "storage_account_id" {}
variable "dmz_subnet_id" {}
variable "ssh_public_key" {}
variable "key_vault_uri" {}
variable "admin_username" {
  default = "adminuser"
}

# ============================================
# PUBLIC IP
# ============================================
resource "azurerm_public_ip" "vm1_pip" {
  name                = "VM1-WebServer-PIP"
  location            = var.location
  resource_group_name = var.resource_group_name
  allocation_method   = "Static"
  sku                 = "Standard"
}

# ============================================
# NETWORK INTERFACE
# ============================================
resource "azurerm_network_interface" "vm1_nic" {
  name                = "VM1-WebServer-NIC"
  location            = var.location
  resource_group_name = var.resource_group_name

  ip_configuration {
    name                          = "vm1-ip-config"
    subnet_id                     = var.dmz_subnet_id
    private_ip_address_allocation = "Static"
    private_ip_address            = "10.10.1.10"
    public_ip_address_id          = azurerm_public_ip.vm1_pip.id
  }
}

# ============================================
# VM1 - UBUNTU WEB SERVER
# ============================================
resource "azurerm_linux_virtual_machine" "vm1_webserver" {
  name                            = "VM1-WebServer"
  location                        = var.location
  resource_group_name             = var.resource_group_name
  size                            = "Standard_B2s"
  admin_username                  = var.admin_username
  disable_password_authentication = true

  admin_ssh_key {
    username   = "adminuser"
    public_key = var.ssh_public_key
  }

  network_interface_ids = [
    azurerm_network_interface.vm1_nic.id
  ]

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "UbuntuServer"
    sku       = "18.04-LTS"
    version   = "latest"
  }

  # Managed Identity - reads secrets from Key Vault
  identity {
    type = "SystemAssigned"
  }
  # Bootstrap script - no secrets inside
  custom_data = base64encode(
    templatefile("${path.module}/scripts/custom_data.sh.tpl", {
      key_vault_uri = var.key_vault_uri
      DOCKER_COMPOSE_VERSION = "v2.24.0"
    })
  )
}

resource "azurerm_role_assignment" "vm1_kv_reader" {
  scope                = var.key_vault_id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_linux_virtual_machine.vm1_webserver.identity[0].principal_id
}

resource "azurerm_role_assignment" "vm1_storage_access" {
  scope                = var.storage_account_id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = azurerm_linux_virtual_machine.vm1_webserver.identity[0].principal_id
}


# ============================================
# AZURE MONITOR AGENT
# ============================================
resource "azurerm_virtual_machine_extension" "ama" {
  name                       = "AzureMonitorLinuxAgent"
  virtual_machine_id         = azurerm_linux_virtual_machine.vm1_webserver.id
  publisher                  = "Microsoft.Azure.Monitor"
  type                       = "AzureMonitorLinuxAgent"
  type_handler_version       = "1.0"
  auto_upgrade_minor_version = true
  depends_on                 = [azurerm_linux_virtual_machine.vm1_webserver]
}

# ============================================
# AUTO SHUTDOWN - 11PM every day
# ============================================
resource "azurerm_dev_test_global_vm_shutdown_schedule" "vm1_shutdown" {
  virtual_machine_id    = azurerm_linux_virtual_machine.vm1_webserver.id
  location              = var.location
  enabled               = true
  daily_recurrence_time = "2300"
  timezone              = "UTC"

  notification_settings {
    enabled = false
  }
}

# ============================================
# JIT - Microsoft Defender
# ============================================
resource "azurerm_security_center_subscription_pricing" "vm_defender" {
  tier          = "Standard"
  resource_type = "VirtualMachines"
}

# ============================================
# OUTPUTS
# ============================================
output "vm1_public_ip" {
  value       = azurerm_public_ip.vm1_pip.ip_address
  description = "Visit DVWA at http://<this_ip>/dvwa"
}

output "vm1_private_ip" {
  value = azurerm_network_interface.vm1_nic.private_ip_address
}

output "vm1_id" {
  value = azurerm_linux_virtual_machine.vm1_webserver.id
}

output "vm1_principal_id" {
  value = azurerm_linux_virtual_machine.vm1_webserver.identity[0].principal_id
}