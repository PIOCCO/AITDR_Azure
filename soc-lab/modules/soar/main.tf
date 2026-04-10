# ============================================
# MODULE: SOAR
# Terraform owns: RBAC + Sentinel rules only
# ARM owns: Logic App definitions
# ============================================

variable "resource_group_name" {}
variable "location" {}
variable "sentinel_workspace_id" {}
variable "sentinel_workspace_name" {}
variable "alert_email" {}
variable "subscription_id" {}
variable "sentinel_principal_id" {}
variable "nsg_name" {}
variable "nsg_soar_id" {}

# ============================================
# ARM DEPLOYMENT - Ban Attacker Logic App
# ARM owns this resource completely
# ============================================
resource "azurerm_resource_group_template_deployment" "ban_attacker" {
  name                = "soar-ban-attacker"
  resource_group_name = var.resource_group_name
  deployment_mode     = "Incremental"

  template_content = templatefile("${path.module}/logic_app.json", {
    location        = var.location
    subscription_id = var.subscription_id
    resource_group  = var.resource_group_name
    nsg_name        = var.nsg_name
  })
}

# ============================================
# ARM DEPLOYMENT - Email Alert Logic App
# ARM owns this resource completely
# ============================================
resource "azurerm_resource_group_template_deployment" "email_alert" {
  name                = "soar-email-alert"
  resource_group_name = var.resource_group_name
  deployment_mode     = "Incremental"

  template_content = templatefile("${path.module}/email_app.json", {
    location    = var.location
    alert_email = var.alert_email
  })
}

# ============================================
# ARM DEPLOYMENT - Cleanup Logic App
# ============================================
resource "azurerm_resource_group_template_deployment" "cleanup_bans" {
  name                = "soar-cleanup-bans"
  resource_group_name = var.resource_group_name
  deployment_mode     = "Incremental"

  template_content = jsonencode({
    "$schema"      = "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#"
    contentVersion = "1.0.0.0"
    resources = [{
      type       = "Microsoft.Logic/workflows"
      apiVersion = "2019-05-01"
      name       = "SOAR-Cleanup-Bans"
      location   = var.location
      identity   = { type = "SystemAssigned" }
      properties = {
        state = "Enabled"
        definition = {
          "$schema"      = "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#"
          contentVersion = "1.0.0.0"
          triggers = {
            Daily_Cleanup = {
              type = "Recurrence"
              recurrence = {
                frequency = "Day"
                interval  = 1
              }
            }
          }
          actions = {}
        }
      }
    }]
  })
}

# ============================================
# ARM DEPLOYMENT - Close False Positives
# ============================================
resource "azurerm_resource_group_template_deployment" "close_false_positive" {
  name                = "soar-close-false-positive"
  resource_group_name = var.resource_group_name
  deployment_mode     = "Incremental"

  template_content = jsonencode({
    "$schema"      = "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#"
    contentVersion = "1.0.0.0"
    resources = [{
      type       = "Microsoft.Logic/workflows"
      apiVersion = "2019-05-01"
      name       = "SOAR-Close-False-Positive"
      location   = var.location
      identity   = { type = "SystemAssigned" }
      properties = {
        state = "Enabled"
        definition = {
          "$schema"      = "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#"
          contentVersion = "1.0.0.0"
          triggers = {
            When_Incident = {
              type = "Request"
              kind = "Http"
              inputs = {
                schema = {
                  type = "object"
                  properties = {
                    incidentId = { type = "string" }
                  }
                }
              }
            }
          }
          actions = {}
        }
      }
    }]
  })
}

# ============================================
# RBAC - Terraform owns identity assignments
# Get Logic App principal IDs from ARM outputs
# ============================================
data "azurerm_logic_app_workflow" "ban_attacker" {
  name                = "SOAR-Ban-Attacker"
  resource_group_name = var.resource_group_name
  depends_on          = [azurerm_resource_group_template_deployment.ban_attacker]
}

resource "azurerm_role_assignment" "soar_network_contributor" {
  scope                = var.nsg_soar_id
  role_definition_name = "Network Contributor"
  principal_id         = data.azurerm_logic_app_workflow.ban_attacker.identity[0].principal_id
  depends_on           = [azurerm_resource_group_template_deployment.ban_attacker]
}

resource "azurerm_role_assignment" "soar_vm_contributor" {
  scope                = "/subscriptions/${var.subscription_id}/resourceGroups/${var.resource_group_name}/providers/Microsoft.Compute/virtualMachines/VM1-WebServer"
  role_definition_name = "Virtual Machine Contributor"
  principal_id         = data.azurerm_logic_app_workflow.ban_attacker.identity[0].principal_id
  depends_on           = [azurerm_resource_group_template_deployment.ban_attacker]
}

# ============================================
# SENTINEL AUTOMATION RULES
# Terraform owns Sentinel resources
# ============================================
resource "azurerm_sentinel_automation_rule" "auto_ban" {
  name                       = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
  log_analytics_workspace_id = var.sentinel_workspace_id
  display_name               = "Auto Ban Brute Force Attackers"
  order                      = 1
  enabled                    = true
  triggers_on                = "Incidents"
  triggers_when              = "Created"

  condition_json = jsonencode([{
    conditionType = "Property"
    conditionProperties = {
      propertyName   = "IncidentSeverity"
      operator       = "Equals"
      propertyValues = ["High"]
    }
  }])

  action_incident {
    order    = 1
    status   = "Active"
    severity = "High"
  }
}

resource "azurerm_sentinel_automation_rule" "web_attack_response" {
  name                       = "8c4e5d3b-2345-6789-bcde-f01234567890"
  log_analytics_workspace_id = var.sentinel_workspace_id
  display_name               = "Auto Respond To Web Attacks"
  order                      = 2
  enabled                    = true
  triggers_on                = "Incidents"
  triggers_when              = "Created"

  action_incident {
    order    = 1
    status   = "Active"
    severity = "Medium"
  }
}

# ============================================
# OUTPUTS
# ============================================
output "soar_ban_attacker_name" {
  value = "SOAR-Ban-Attacker"
}

output "soar_email_alert_name" {
  value = "SOAR-Email-Alert"
}

output "soar_cleanup_name" {
  value = "SOAR-Cleanup-Bans"
}

output "soar_email_alert_id" {
  value = azurerm_resource_group_template_deployment.email_alert.id
}

output "soar_ban_attacker_id" {
  value = azurerm_resource_group_template_deployment.ban_attacker.id
}