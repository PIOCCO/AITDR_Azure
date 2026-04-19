# ============================================
# MODULE: KEY VAULT
# Stores all secrets - no plaintext anywhere
# ============================================

variable "resource_group_name" {}
variable "location" {}
variable "tenant_id" {}
variable "admin_object_id" {}  # Your personal Azure AD object ID

variable "secrets" {
  description = "Map of secret name => value"
  type        = map(string)
}

# ============================================
# KEY VAULT
# ============================================
resource "azurerm_key_vault" "aitdr_kv" {
  name                        = "aitdr-kv-${random_string.suffix.result}"
  location                    = var.location
  resource_group_name         = var.resource_group_name
  tenant_id                   = var.tenant_id
  sku_name                    = "standard"
  soft_delete_retention_days  = 7
  purge_protection_enabled    = true
  rbac_authorization_enabled   = true

  tags = {
    environment = "SOC-Lab"
    project     = "AITDR"
  }
}

resource "random_string" "suffix" {
  length  = 6
  special = false
  upper   = false
}

# ============================================
# RBAC - Admin can manage secrets
# ============================================
resource "azurerm_role_assignment" "admin_kv_officer" {
  scope                = azurerm_key_vault.aitdr_kv.id
  role_definition_name = "Key Vault Secrets Officer"
  principal_id         = var.admin_object_id
}


# ============================================
# SECRETS - Stored in Key Vault
# ============================================
resource "azurerm_key_vault_secret" "secrets" {
  for_each     = var.secrets
  name         = each.key
  value        = each.value
  key_vault_id = azurerm_key_vault.aitdr_kv.id

  depends_on = [
    azurerm_role_assignment.admin_kv_officer
  ]
}

# ============================================
# OUTPUTS
# ============================================
output "key_vault_id" {
  value = azurerm_key_vault.aitdr_kv.id
}

output "key_vault_uri" {
  value = azurerm_key_vault.aitdr_kv.vault_uri
}

output "key_vault_name" {
  value = azurerm_key_vault.aitdr_kv.name
}
