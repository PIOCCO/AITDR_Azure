terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 3.84.0"
    }
    cloudinit = {
      source  = "hashicorp/cloudinit"
      version = ">= 2.3.0"
    }
  }
}

provider "azurerm" {
  features {}
}

resource "azurerm_resource_group" "soc_lab" {
  name     = var.resource_group_name
  location = var.location

  lifecycle {
    prevent_destroy = true
  }
}


module "hub_vnet" {
  source              = "./modules/hub_vnet"
  resource_group_name = azurerm_resource_group.soc_lab.name
  location            = azurerm_resource_group.soc_lab.location
}

module "vnet1" {
  source              = "./modules/vnet1"
  resource_group_name = azurerm_resource_group.soc_lab.name
  location            = azurerm_resource_group.soc_lab.location
}

module "vnet2" {
  source              = "./modules/vnet2"
  resource_group_name = azurerm_resource_group.soc_lab.name
  location            = azurerm_resource_group.soc_lab.location
  dmz_subnet_id       = module.vnet1.dmz_subnet_id
  data_subnet_id      = module.vnet2.data_subnet_id
}

module "vnet3" {
  source              = "./modules/vnet3"
  resource_group_name = azurerm_resource_group.soc_lab.name
  location            = azurerm_resource_group.soc_lab.location
}

module "peerings" {
  source              = "./modules/peerings"
  resource_group_name = azurerm_resource_group.soc_lab.name

  hub_vnet_id   = module.hub_vnet.hub_vnet_id
  hub_vnet_name = module.hub_vnet.hub_vnet_name

  vnet1_id   = module.vnet1.vnet1_id
  vnet1_name = module.vnet1.vnet1_name

  vnet2_id   = module.vnet2.vnet2_id
  vnet2_name = module.vnet2.vnet2_name

  vnet3_id   = module.vnet3.vnet3_id
  vnet3_name = module.vnet3.vnet3_name
}

module "nsg" {
  source              = "./modules/nsg"
  resource_group_name = azurerm_resource_group.soc_lab.name
  location            = azurerm_resource_group.soc_lab.location
  kali_ip             = var.kali_ip

  dmz_subnet_id   = module.vnet1.dmz_subnet_id
  vm_ad_subnet_id = module.vnet1.vm_ad_subnet_id
  data_subnet_id  = module.vnet2.data_subnet_id
  siem_subnet_id  = module.vnet3.siem_subnet_id
  soar_subnet_id  = module.vnet3.soar_subnet_id
}

module "key_vault" {
  source = "./modules/key_vault"

  resource_group_name = var.resource_group_name
  location            = var.location
  tenant_id           = var.tenant_id
  admin_object_id     = var.admin_object_id

  secrets = {
    "sql-server-fqdn"      = module.sql_database.sql_server_fqdn
    "sql-admin-password"   = var.sql_admin_password
    "storage-account-name" = module.vnet2.storage_account_name
  }
}

module "vm1_webserver" {
  source              = "./modules/vm1_webserver"
  resource_group_name = azurerm_resource_group.soc_lab.name
  location            = azurerm_resource_group.soc_lab.location
  dmz_subnet_id       = module.vnet1.dmz_subnet_id
  ssh_public_key      = var.ssh_public_key
  key_vault_uri       = module.key_vault.key_vault_uri
  key_vault_id        = module.key_vault.key_vault_id
  storage_account_id  = module.vnet2.storage_account_id

  depends_on = [module.key_vault]
}

module "sql_database" {
  source               = "./modules/sql_database"
  resource_group_name  = var.resource_group_name
  location             = var.location
  sql_admin_login      = "sqladmin"
  sql_admin_password   = var.sql_admin_password
  storage_account_name = module.vnet2.storage_account_name
  allowed_ip           = var.allowed_ip
}

module "sentinel" {
  source              = "./modules/sentinel"
  resource_group_name = var.resource_group_name
  location            = var.location
}

resource "azurerm_monitor_data_collection_rule_association" "vm_logs" {
  name                    = "vm1-logs"
  target_resource_id      = module.vm1_webserver.vm1_id
  data_collection_rule_id = module.sentinel.linux_syslog_dcr_id
}

module "soar" {
  source                  = "./modules/soar"
  resource_group_name     = var.resource_group_name
  location                = var.location
  sentinel_workspace_id   = module.sentinel.sentinel_workspace_id
  sentinel_workspace_name = "aitdr-sentinel-workspace"
  alert_email             = var.alert_email
  subscription_id         = var.subscription_id
  nsg_name                = var.nsg_name
  sentinel_principal_id   = var.sentinel_principal_id
  nsg_soar_id             = module.nsg.nsg_soar_id

  depends_on = [module.vm1_webserver]
}

module "vm2_ml" {
  source                 = "./modules/vm2_ml"
  resource_group_name    = var.resource_group_name
  location               = var.location
  analytics_subnet_id    = module.vnet2.analytics_subnet_id
  ssh_public_key         = var.ssh_public_key
  sql_server_fqdn        = module.sql_database.sql_server_fqdn
  sql_admin_password     = var.sql_admin_password
  sentinel_workspace_id  = module.sentinel.sentinel_workspace_id
  sentinel_workspace_key = module.sentinel.sentinel_workspace_key
  storage_account_name   = module.vnet2.storage_account_name
}

# module "vpn" {
#   source               = "./modules/vpn"
#   resource_group_name  = var.resource_group_name
#   location             = var.location
#   gateway_subnet_id    = module.vnet2.gateway_subnet_id
#   vpn_root_certificate = var.vpn_root_certificate
# }

module "data_sources" {
  source                  = "./modules/data_sources"
  resource_group_name     = var.resource_group_name
  location                = var.location
  storage_account_id      = module.vnet2.storage_account_id
  storage_account_name    = module.vnet2.storage_account_name
  sentinel_workspace_id   = module.sentinel.sentinel_workspace_id
  sentinel_workspace_name = "aitdr-sentinel-workspace"
  network_watcher_name    = module.data_sources.nw_name
  network_watcher_rg      = module.data_sources.nw_rg
  nsg_dmz_id              = module.nsg.nsg_dmz_id
  sentinel_workspace_guid = module.sentinel.workspace_guid
  dmz_subnet_id           = module.vnet1.dmz_subnet_id
}