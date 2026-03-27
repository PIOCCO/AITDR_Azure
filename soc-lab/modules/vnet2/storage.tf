# ============================================
# AZURE STORAGE ACCOUNT
# Stores all logs from VM1
# ============================================

resource "azurerm_storage_account" "logs_storage" {
  name                     = "aitdrlogs${random_string.suffix.result}"
  resource_group_name      = var.resource_group_name
  location                 = var.location
  account_tier             = "Standard"
  account_replication_type = "LRS"      # cheapest option

  # Only allow access from Vnet1 and Vnet2
  network_rules {
    default_action             = "Allow"
    virtual_network_subnet_ids = [
      var.dmz_subnet_id,      # VM1 can upload logs
      var.data_subnet_id      # Vnet2 can read logs
    ]
  }
}

# Random suffix so storage name is unique
resource "random_string" "suffix" {
  length  = 6
  special = false
  upper   = false
}

# Container to store log files
resource "azurerm_storage_container" "logs_container" {
  name                  = "attack-logs"
  storage_account_name  = azurerm_storage_account.logs_storage.name  
  container_access_type = "private"
}

# Output storage details
output "storage_account_name" {
  value = azurerm_storage_account.logs_storage.name
}

output "storage_container_name" {
  value = azurerm_storage_container.logs_container.name
}

output "storage_connection_string" {
  value     = azurerm_storage_account.logs_storage.primary_connection_string
  sensitive = true
}

output "storage_account_id" {
  value = azurerm_storage_account.logs_storage.id
}