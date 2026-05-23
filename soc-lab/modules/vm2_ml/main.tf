# ============================================
# MODULE: VM2 ML ANALYSIS
# Internal VM - No public IP
# Unsupervised ML on attack logs
# ============================================

variable "resource_group_name" {}
variable "location" {}
variable "analytics_subnet_id" {}
variable "ssh_public_key" {}
variable "sql_server_fqdn" {}
variable "sql_admin_password" {}
variable "sentinel_workspace_id" {}
variable "storage_account_name" {}
variable "sentinel_workspace_key" {
  type = string
}
variable "admin_username" {
  default = "adminuser"
}

# ============================================
# NETWORK INTERFACE - No Public IP
# ============================================
resource "azurerm_network_interface" "vm2_nic" {
  name                = "VM2-ML-NIC"
  location            = var.location
  resource_group_name = var.resource_group_name

  ip_configuration {
    name                          = "vm2-ip-config"
    subnet_id                     = var.analytics_subnet_id
    private_ip_address_allocation = "Static"
    private_ip_address            = "10.10.2.40"
  }
}

# ============================================
# NETWORK INTERFACE - LOG ANALYTICS READER ROLE
# ============================================
resource "azurerm_role_assignment" "vm2_logs_reader" {
  scope                = var.sentinel_workspace_id
  role_definition_name = "Log Analytics Reader"
  principal_id         = azurerm_linux_virtual_machine.vm2_ml.identity[0].principal_id

  depends_on = [
    azurerm_linux_virtual_machine.vm2_ml
  ]
}

# ============================================
# CLOUD-INIT CONFIG
# ============================================
data "cloudinit_config" "vm2_config" {
  gzip          = true
  base64_encode = true

  part {
    content_type = "text/cloud-config"
    content = jsonencode({
      write_files = [
        {
          path        = "/var/lib/aitdr/bootstrap.sh"
          permissions = "0755"
          owner       = "root:root"
          content     = file("${path.module}/scripts/bootstrap.sh")
        },
        {
          path        = "/var/lib/aitdr/ml_anomaly_detection.py"
          permissions = "0755"
          owner       = "root:root"
          content = templatefile("${path.module}/scripts/ml_anomaly_detection.py", {
            sql_server_fqdn    = var.sql_server_fqdn
            sql_admin_password = var.sql_admin_password
          })
        }
      ]
      runcmd = [
        ["/bin/bash", "/var/lib/aitdr/bootstrap.sh"]
      ]
    })
  }
}

# ============================================
# VM2 - ML ANALYSIS SERVER
# ============================================
resource "azurerm_linux_virtual_machine" "vm2_ml" {
  name                            = "VM2-ML-Analysis"
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
    azurerm_network_interface.vm2_nic.id
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

  identity {
    type = "SystemAssigned"
  }

  custom_data = data.cloudinit_config.vm2_config.rendered
}

# ============================================
# AZURE MONITOR AGENT
# ============================================
resource "azurerm_virtual_machine_extension" "ama" {
  name                       = "AzureMonitorLinuxAgent"
  virtual_machine_id         = azurerm_linux_virtual_machine.vm2_ml.id
  publisher                  = "Microsoft.Azure.Monitor"
  type                       = "AzureMonitorLinuxAgent"
  type_handler_version       = "1.0"
  auto_upgrade_minor_version = true
  depends_on                 = [azurerm_linux_virtual_machine.vm2_ml]
}

# ============================================
# AUTO SHUTDOWN - 11PM
# ============================================
resource "azurerm_dev_test_global_vm_shutdown_schedule" "vm2_shutdown" {
  virtual_machine_id    = azurerm_linux_virtual_machine.vm2_ml.id
  location              = var.location
  enabled               = true
  daily_recurrence_time = "2300"
  timezone              = "UTC"
  notification_settings {
    enabled = false
  }
}

# ============================================
# OUTPUTS
# ============================================
output "vm2_private_ip" {
  value = azurerm_network_interface.vm2_nic.private_ip_address
}

output "vm2_id" {
  value = azurerm_linux_virtual_machine.vm2_ml.id
}

output "vm2_principal_id" {
  value = azurerm_linux_virtual_machine.vm2_ml.identity[0].principal_id
}