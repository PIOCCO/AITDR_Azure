# ============================================
# MODULE: DATA SOURCES
# NSG Flow Logs + Azure Activity Logs
# ============================================

variable "resource_group_name" {}
variable "location" {}
variable "storage_account_id" {}
variable "storage_account_name" {}
variable "network_watcher_name" {}
variable "network_watcher_rg" {}
variable "sentinel_workspace_id" {}
variable "sentinel_workspace_guid" {}
variable "dmz_subnet_id" {}
variable "sentinel_workspace_name" {}
variable "nsg_dmz_id" {}

# ============================================
# VNET FLOW LOGS - DMZ
# Captures all traffic in the subnet
# ============================================
resource "azurerm_network_watcher_flow_log" "vnet_dmz_flow" {
  name                  = "vnet-dmz-flow-logs"
  network_watcher_name  = azurerm_network_watcher.nw.name
  resource_group_name   = azurerm_network_watcher.nw.resource_group_name
  target_resource_id    = var.dmz_subnet_id
  storage_account_id    = var.storage_account_id
  enabled               = true
  version               = 2

  retention_policy {
    enabled = true
    days    = 7
  }

  traffic_analytics {
    enabled               = true
    workspace_id          = var.sentinel_workspace_guid
    workspace_region      = var.location
    workspace_resource_id = var.sentinel_workspace_id
    interval_in_minutes   = 10
  }

  tags = {
    environment = "SOC-Lab"
    project     = "AITDR"
  }
}


resource "azurerm_network_watcher" "nw" {
  name                = "NetworkWatcher_switzerlandnorth"
  location            = "Switzerland North"
  resource_group_name = "NetworkWatcherRG"
}


# ============================================
# DIAGNOSTIC SETTINGS
# Send Activity Logs to Sentinel workspace
# ============================================
resource "azurerm_monitor_diagnostic_setting" "activity_logs" {
  name               = "aitdr-activity-logs"
  target_resource_id = "/subscriptions/0afc9ce0-c21e-4814-ae66-7792fa3ed6c1"

  log_analytics_workspace_id = var.sentinel_workspace_id

  enabled_log {
    category = "Administrative"
  }

  enabled_log {
    category = "Security"
  }

  enabled_log {
    category = "ServiceHealth"
  }

  enabled_log {
    category = "Alert"
  }

  enabled_log {
    category = "Policy"
  }
}

# ============================================
# DEFENDER FOR CLOUD
# Vulnerability + threat detection
# ============================================
resource "azurerm_security_center_subscription_pricing" "defender_sql" {
  tier          = "Standard"
  resource_type = "SqlServers"
}

resource "azurerm_security_center_subscription_pricing" "defender_storage" {
  tier          = "Standard"
  resource_type = "StorageAccounts"
}

resource "azurerm_security_center_subscription_pricing" "defender_dns" {
  tier          = "Standard"
  resource_type = "Dns"
}

# ============================================
# OUTPUTS
# ============================================
output "flow_log_id" {
  value = azurerm_network_watcher_flow_log.vnet_dmz_flow.id
}

output "nw_name" {
  value = azurerm_network_watcher.nw.name
}

output "nw_rg" {
  value = azurerm_network_watcher.nw.resource_group_name
}