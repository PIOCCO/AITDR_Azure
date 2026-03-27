# ============================================
# MODULE: MICROSOFT SENTINEL (SIEM)
# Deployed in VNet3 SIEM subnet
# ============================================

variable "resource_group_name" {}
variable "location" {}

# ============================================
# LOG ANALYTICS WORKSPACE
# Sentinel lives inside this workspace
# ============================================
resource "azurerm_log_analytics_workspace" "sentinel_workspace" {
  name                = "aitdr-sentinel-workspace"
  location            = var.location
  resource_group_name = var.resource_group_name
  sku                 = "PerGB2018"
  retention_in_days   = 30

  tags = {
    environment = "SOC-Lab"
    project     = "AITDR"
  }
}

# ============================================
# ENABLE MICROSOFT SENTINEL
# ============================================
resource "azurerm_sentinel_log_analytics_workspace_onboarding" "sentinel" {
  workspace_id = azurerm_log_analytics_workspace.sentinel_workspace.id
}

# ============================================
# SENTINEL ALERT RULE 1 - SSH Brute Force
# ============================================
resource "azurerm_sentinel_alert_rule_scheduled" "ssh_brute_force" {
  name                       = "SSH-Brute-Force-Detection"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.sentinel_workspace.id
  display_name               = "SSH Brute Force Attack Detected"
  severity                   = "High"
  enabled                    = true

  depends_on = [azurerm_sentinel_log_analytics_workspace_onboarding.sentinel]

  query = <<-QUERY
    Syslog
    | where Facility == "auth"
    | where SyslogMessage contains "Invalid user"
    | summarize Count = count() by HostIP, bin(TimeGenerated, 5m)
    | where Count > 10
  QUERY

  query_frequency = "PT5M"
  query_period    = "PT5M"
  trigger_operator  = "GreaterThan"
  trigger_threshold = 0
  tactics = ["CredentialAccess", "InitialAccess"]
}

# ============================================
# SENTINEL ALERT RULE 2 - Web Attacks
# ============================================
resource "azurerm_sentinel_alert_rule_scheduled" "web_attack" {
  name                       = "Web-Attack-Detection"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.sentinel_workspace.id
  display_name               = "Web Attack Detected on DVWA"
  severity                   = "Medium"
  enabled                    = true

  depends_on = [azurerm_sentinel_log_analytics_workspace_onboarding.sentinel]

  query = <<-QUERY
    Syslog
    | where SyslogMessage contains "select" 
        or SyslogMessage contains "union"
        or SyslogMessage contains "<script>"
        or SyslogMessage contains "../"
    | summarize Count = count() by HostIP, bin(TimeGenerated, 5m)
    | where Count > 5
  QUERY

  query_frequency = "PT5M"
  query_period    = "PT5M"
  trigger_operator  = "GreaterThan"
  trigger_threshold = 0
  tactics = ["InitialAccess", "Execution"]
}

# ============================================
# SENTINEL ALERT RULE 3 - Mozi Botnet
# ============================================
resource "azurerm_sentinel_alert_rule_scheduled" "mozi_botnet" {
  name                       = "Mozi-Botnet-Detection"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.sentinel_workspace.id
  display_name               = "Mozi Botnet Activity Detected"
  severity                   = "High"
  enabled                    = true

  depends_on = [azurerm_sentinel_log_analytics_workspace_onboarding.sentinel] 
  
  query = <<-QUERY
    Syslog
    | where SyslogMessage contains "Mozi.m"
        or SyslogMessage contains "setup.cgi"
    | summarize Count = count() by HostIP, bin(TimeGenerated, 1h)
  QUERY

  query_frequency = "PT1H"
  query_period    = "PT1H"
  trigger_operator  = "GreaterThan"
  trigger_threshold = 0
  tactics = ["CommandAndControl"]
}

resource "azurerm_monitor_data_collection_rule" "linux_syslog" {
  name                = "linux-syslog-dcr"
  location            = var.location
  resource_group_name = var.resource_group_name

  destinations {
    log_analytics {
      name                  = "sentinel-destination"
      workspace_resource_id = azurerm_log_analytics_workspace.sentinel_workspace.id
    }
  }

  data_sources {
    syslog {
      name           = "linux-syslog"
      facility_names = ["auth", "authpriv", "daemon", "syslog"]
      log_levels     = ["Error", "Warning", "Info", "Notice", "Critical"]
      streams        = ["Microsoft-Syslog"]
    }
  }

  data_flow {
    streams      = ["Microsoft-Syslog"]
    destinations = ["sentinel-destination"]
  }
}

# ============================================
# SENTINEL ALERT RULE 4 - SQL Injection
# ============================================

resource "azurerm_sentinel_alert_rule_scheduled" "sql_injection_attack" {
  name                       = "SQL-Injection-Detection"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.sentinel_workspace.id
  display_name               = "SQL Injection Attack Detected"
  severity                   = "High"
  enabled                    = true

  depends_on = [azurerm_sentinel_log_analytics_workspace_onboarding.sentinel]

  query = <<-QUERY
    Syslog
    | where SyslogMessage matches regex @"(?i)(union\s+select|or\s+1=1|information_schema|sleep\(|benchmark\(|--\s)"
    | summarize Count = count() by HostIP, bin(TimeGenerated, 5m)
    | where Count > 5
  QUERY

  query_frequency = "PT5M"
  query_period    = "PT5M"

  trigger_operator  = "GreaterThan"
  trigger_threshold = 0

  tactics = ["InitialAccess", "Execution"]
}

# ====================================================================
# SENTINEL ALERT RULE 5 - Abuse Elevation Control Mechanism
# ====================================================================

resource "azurerm_sentinel_alert_rule_scheduled" "priv_escalation" {
  name                       = "Priv-Escalation-Detection"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.sentinel_workspace.id
  display_name               = "Possible Sudo Abuse Detected"
  severity                   = "High"
  enabled                    = true

  query = <<-QUERY
    Syslog
    | where SyslogMessage contains "sudo"
    | summarize Count=count() by HostIP, bin(TimeGenerated, 5m)
    | where Count > 5
  QUERY

  query_frequency = "PT5M"
  query_period    = "PT5M"
  trigger_operator = "GreaterThan"
  trigger_threshold = 0
  tactics = ["PrivilegeEscalation"]
}

# ====================================================================
# SENTINEL ALERT RULE 6 - Suspicious Login Activity
# ====================================================================

resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_login" {
  name                       = "Suspicious-Login-Detection"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.sentinel_workspace.id
  display_name               = "Suspicious Login Detected"
  severity                   = "High"
  enabled                    = true

  query = <<-QUERY
    SecurityEvent
    | where EventID == 4625
    | summarize Count = count() by Account, IpAddress, bin(TimeGenerated, 5m)
    | where Count > 3
  QUERY

  query_frequency = "PT5M"
  query_period    = "PT5M"
  trigger_operator  = "GreaterThan"
  trigger_threshold = 0
  tactics = ["CredentialAccess"]
}

# =====================================================
# SENTINEL ALERT RULE 7 - Abnormal Process Execution
# =====================================================

resource "azurerm_sentinel_alert_rule_scheduled" "abnormal_process" {
  name                       = "Abnormal-Process-Detection"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.sentinel_workspace.id
  display_name               = "Suspicious Process Detected"
  severity                   = "Medium"
  enabled                    = true

  query = <<-QUERY
    Syslog
    | where ProcessName in ("nc", "curl", "wget", "powershell")
    | summarize Count = count() by HostIP, ProcessName, bin(TimeGenerated, 5m)
    | where Count > 2
  QUERY

  query_frequency = "PT5M"
  query_period    = "PT5M"
  trigger_operator  = "GreaterThan"
  trigger_threshold = 0
  tactics = ["Execution"]
}

# ===========================================================
# SENTINEL ALERT RULE 8 - Potential Data Exfiltration
# ===========================================================

resource "azurerm_sentinel_alert_rule_scheduled" "data_exfiltration" {
  name                       = "Data-Exfiltration-Detection"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.sentinel_workspace.id
  display_name               = "Potential Data Exfiltration Detected"
  severity                   = "High"
  enabled                    = true

  query = <<-QUERY
    Syslog
    | where ProcessName in ("scp","rsync")
    | summarize Count=count() by HostIP, ProcessName, bin(TimeGenerated, 15m)
    | where Count > 5
  QUERY

  query_frequency = "PT15M"
  query_period    = "PT15M"
  trigger_operator  = "GreaterThan"
  trigger_threshold = 0
  tactics = ["Exfiltration"]
}

# ==================================================
# SENTINEL ALERT RULE - Container Admin Commands 
# ==================================================
resource "azurerm_sentinel_alert_rule_scheduled" "docker_admin_cmds" {
  name                       = "Docker-Admin-Command-Detection"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.sentinel_workspace.id
  display_name               = "Suspicious Docker Container Commands Detected"
  severity                   = "High"
  enabled                    = true

  depends_on = [azurerm_sentinel_log_analytics_workspace_onboarding.sentinel]

  query = <<-QUERY
    ContainerLog
    | where LogEntry matches regex @"(?i)(docker\s+(exec|run|cp|commit).*)"
    | summarize Count=count() by ContainerID, Computer, bin(TimeGenerated, 5m)
    | where Count > 3
  QUERY

  query_frequency = "PT5M"
  query_period    = "PT5M"

  trigger_operator  = "GreaterThan"
  trigger_threshold = 0
  tactics           = ["PrivilegeEscalation", "LateralMovement"]
}

# ============================================
# OUTPUTS
# ============================================
output "sentinel_workspace_id" {
  value = azurerm_log_analytics_workspace.sentinel_workspace.id
}

output "linux_syslog_dcr_id" {
  value = azurerm_monitor_data_collection_rule.linux_syslog.id
}

output "sentinel_workspace_key" {
  value = azurerm_log_analytics_workspace.sentinel_workspace.primary_shared_key
}
