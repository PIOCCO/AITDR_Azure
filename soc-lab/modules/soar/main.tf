# ============================================
# MODULE: LOGIC APPS SOAR
# Auto responds to Sentinel incidents
# ============================================

variable "resource_group_name" {}
variable "location" {}
variable "sentinel_workspace_id" {}
variable "sentinel_workspace_name" {}
variable "alert_email" {}
variable "subscription_id" {}
variable "nsg_name" {}


# ============================================
# LOGIC APP 1 - Auto Ban SSH Attackers
# Triggers on SSH Brute Force incident
# ============================================
resource "azurerm_logic_app_workflow" "ban_ssh_attacker" {
  name                = "SOAR-Ban-SSH-Attacker"
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

# ============================================
# LOGIC APP 2 - Email Alert On Attack
# Sends email when any incident created
# ============================================
resource "azurerm_logic_app_workflow" "email_alert" {
  name                = "SOAR-Email-Alert"
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

# ============================================
# LOGIC APP 3 - Auto Close False Positives
# Closes incidents from known safe IPs
# ============================================
resource "azurerm_logic_app_workflow" "close_false_positive" {
  name                = "SOAR-Close-False-Positive"
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

# ============================================
# TRIGGER - SSH Brute Force
# Runs when Sentinel creates SSH incident
# ============================================
resource "azurerm_logic_app_trigger_http_request" "ssh_trigger" {
  name         = "When-SSH-Incident-Created"
  logic_app_id = azurerm_logic_app_workflow.ban_ssh_attacker.id

  schema = jsonencode({
    type = "object"
    properties = {
      incidentId = { type = "string" }
      attackerIP = { type = "string" }
      severity   = { type = "string" }
    }
  })
}

# ============================================
# ACTION - Block Attacker IP (SSH brute force)
# ============================================
resource "azurerm_logic_app_action_http" "block_ssh_attacker_ip" {
  name         = "Block-Attacker-IP"
  logic_app_id = azurerm_logic_app_workflow.ban_ssh_attacker.id

  method = "PUT"

  uri = "https://management.azure.com/subscriptions/${var.subscription_id}/resourceGroups/${var.resource_group_name}/providers/Microsoft.Network/networkSecurityGroups/${var.nsg_name}/securityRules/deny-ssh-attacker?api-version=2023-05-01"

  headers = {
    Content-Type = "application/json"
  }

  body = jsonencode({
    properties = {
      priority                 = 300
      direction                = "Inbound"
      access                   = "Deny"
      protocol                 = "Tcp"
      sourceAddressPrefix      = "@{triggerBody()?['attackerIP']}"
      sourcePortRange          = "*"
      destinationAddressPrefix = "*"
      destinationPortRange     = "22"
      description              = "Auto blocked by SOAR SSH detection"
    }
  })

  depends_on = [
    azurerm_logic_app_trigger_http_request.ssh_trigger
  ]
}

# ============================================
# TRIGGER - Email Alert
# ============================================
resource "azurerm_logic_app_trigger_http_request" "email_trigger" {
  name         = "When-Any-Incident-Created"
  logic_app_id = azurerm_logic_app_workflow.email_alert.id

  schema = jsonencode({
    type = "object"
    properties = {
      incidentId   = { type = "string" }
      incidentName = { type = "string" }
      severity     = { type = "string" }
      description  = { type = "string" }
    }
  })
}

# ============================================
# ACTION - Send Email On Attack
# ============================================
resource "azurerm_logic_app_action_http" "send_email" {
  name         = "Send-Email-Alert"
  logic_app_id = azurerm_logic_app_workflow.email_alert.id

  method = "POST"
  uri    = "https://prod-00.eastus.logic.azure.com/workflows/sendmail"

  body = jsonencode({
    to      = var.alert_email
    subject = "🚨 AITDR Security Alert - New Incident"
    body    = "A new security incident has been detected in your AITDR lab."
  })

  depends_on = [azurerm_logic_app_trigger_http_request.email_trigger]
}
# ============================================
# SENTINEL AUTOMATION RULE - SSH Brute Force
# ============================================
resource "azurerm_sentinel_automation_rule" "ban_ssh" {
  name                       = "7b3f4c2a-1234-5678-abcd-ef0123456789"
  log_analytics_workspace_id = var.sentinel_workspace_id
  display_name               = "Auto Ban SSH Brute Force Attackers"
  order                      = 1
  enabled                    = true

  triggers_on   = "Incidents"
  triggers_when = "Created"

  action_incident {
    order    = 1
    status   = "Active"
    severity = "High"
  }
}

# ============================================
# SENTINEL AUTOMATION RULE - Web Attack
# ============================================
resource "azurerm_sentinel_automation_rule" "web_attack_response" {
  name                       = "8c4e5d3b-2345-6789-bcde-f01234567890"
  log_analytics_workspace_id = var.sentinel_workspace_id
  display_name               = "Auto Respond To Web Attacks"
  order                      = 2
  enabled                    = true

  triggers_on   = "Incidents"
  triggers_when = "Created"

  action_incident {
    order    = 1
    status   = "Active"
    severity = "Medium"
  }
}
# ============================================
# OUTPUTS
# ============================================
output "soar_ban_ssh_id" {
  value = azurerm_logic_app_workflow.ban_ssh_attacker.id
}

output "soar_email_alert_id" {
  value = azurerm_logic_app_workflow.email_alert.id
}

output "soar_ban_ssh_trigger_url" {
  value     = azurerm_logic_app_trigger_http_request.ssh_trigger.callback_url
  sensitive = true
}
