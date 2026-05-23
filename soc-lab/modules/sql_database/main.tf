# ============================================
# MODULE: AZURE SQL DATABASE
# Stores all DVWA + SSH attack logs
# ============================================

variable "resource_group_name" {}
variable "location" {}
variable "sql_admin_login" {}
variable "sql_admin_password" {}
variable "storage_account_name" {}
variable "allowed_ip" {}

resource "random_string" "suffix" {
  length  = 6
  special = false
  upper   = false
}

resource "azurerm_mssql_server" "sql_server" {
  name                         = "aitdr-sql-server-${random_string.suffix.result}"
  resource_group_name          = var.resource_group_name
  location                     = var.location
  version                      = "12.0"
  administrator_login          = var.sql_admin_login
  administrator_login_password = var.sql_admin_password

  tags = {
    environment = "SOC-Lab"
    project     = "AITDR"
  }
}

resource "azurerm_mssql_database" "attack_logs_db" {
  name        = "AttackLogsDB"
  server_id   = azurerm_mssql_server.sql_server.id
  collation   = "SQL_Latin1_General_CP1_CI_AS"
  sku_name    = "Basic"
  max_size_gb = 2

  tags = {
    environment = "SOC-Lab"
    project     = "AITDR"
  }
}

resource "azurerm_mssql_firewall_rule" "allow_kali" {
  name             = "Allow-Kali"
  server_id        = azurerm_mssql_server.sql_server.id
  start_ip_address = var.allowed_ip
  end_ip_address   = var.allowed_ip
}

resource "azurerm_mssql_firewall_rule" "allow_azure_services" {
  name             = "Allow-Azure-Services"
  server_id        = azurerm_mssql_server.sql_server.id
  start_ip_address = "0.0.0.0"
  end_ip_address   = "0.0.0.0"
}

resource "azurerm_data_factory" "adf" {
  name                = "aitdr-adf-${random_string.suffix.result}"
  location            = var.location
  resource_group_name = var.resource_group_name

  identity {
    type = "SystemAssigned"
  }

  tags = {
    environment = "SOC-Lab"
    project     = "AITDR"
  }
}

resource "azurerm_data_factory_linked_service_azure_blob_storage" "storage_link" {
  name              = "LinkedService-BlobStorage"
  data_factory_id   = azurerm_data_factory.adf.id
  connection_string = "DefaultEndpointsProtocol=https;AccountName=${var.storage_account_name};EndpointSuffix=core.windows.net"
}

resource "azurerm_data_factory_linked_service_azure_sql_database" "sql_link" {
  name              = "LinkedService-SQLDatabase"
  data_factory_id   = azurerm_data_factory.adf.id
  connection_string = "Server=tcp:${azurerm_mssql_server.sql_server.fully_qualified_domain_name},1433;Database=${azurerm_mssql_database.attack_logs_db.name};User ID=${var.sql_admin_login};Password=${var.sql_admin_password};Encrypt=yes;TrustServerCertificate=no;"
}

output "sql_server_name" {
  value = azurerm_mssql_server.sql_server.name
}

output "sql_server_fqdn" {
  value = azurerm_mssql_server.sql_server.fully_qualified_domain_name
}

output "sql_database_name" {
  value = azurerm_mssql_database.attack_logs_db.name
}

output "data_factory_name" {
  value = azurerm_data_factory.adf.name
}