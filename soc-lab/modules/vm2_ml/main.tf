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
    sku = "18.04-LTS"
    version   = "latest"
  }

  identity {
    type = "SystemAssigned"
  }

  custom_data = base64encode(<<-EOF
#!/bin/bash
export DEBIAN_FRONTEND=noninteractive

sudo dpkg --configure -a
sudo apt-get install -f -y

while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; do
  sleep 10
done

# ============================================
# INSTALL PACKAGES
# ============================================
apt-get update -y
apt-get install -y \
  python3-pip \
  python3-dev \
  unixodbc-dev \
  curl \
  git

# ============================================
# INSTALL ODBC FOR SQL
# ============================================
curl https://packages.microsoft.com/keys/microsoft.asc | apt-key add -
curl https://packages.microsoft.com/config/ubuntu/18.04/prod.list > /etc/apt/sources.list.d/mssql-release.list
apt-get update -y
ACCEPT_EULA=Y apt-get install -y msodbcsql17

# ============================================
# INSTALL AZURE CLI
# ============================================
curl -sL https://aka.ms/InstallAzureCLIDeb | bash

# ============================================
# INSTALL ML LIBRARIES
# ============================================
pip3 install \
  scikit-learn \
  pandas \
  numpy \
  pyodbc \
  azure-monitor-query \
  azure-identity \
  joblib

# ============================================
# CREATE ML SCRIPT
# ============================================
cat > /home/adminuser/ml_anomaly_detection.py <<PYTHON
#!/usr/bin/env python3
import pyodbc
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import DBSCAN
from azure.monitor.query import LogsQueryClient
from azure.identity import ManagedIdentityCredential
import joblib
import os

# ============================================
# CONFIG
# ============================================
WORKSPACE_ID = "${var.sentinel_workspace_id}"
SQL_SERVER   = "${var.sql_server_fqdn}"
SQL_DB       = "AttackLogsDB"
SQL_USER     = "sqladmin"
SQL_PASS     = "${var.sql_admin_password}"
MODEL_PATH   = "/home/adminuser/models"

os.makedirs(MODEL_PATH, exist_ok=True)
print(f"[{datetime.now()}] Starting ML anomaly detection...")

# ============================================
# CONNECT TO LOG ANALYTICS
# ============================================
try:
  credential  = ManagedIdentityCredential()
  logs_client = LogsQueryClient(credential)

  ssh_query = """
  Syslog
  | where TimeGenerated > ago(24h)
  | where Facility == "auth"
  | where SyslogMessage contains "Invalid user"
  | extend AttackerIP = extract(@"(\d+\.\d+\.\d+\.\d+)", 1, SyslogMessage)
  | summarize
      SSHAttempts = count(),
      UniqueIPs   = dcount(AttackerIP),
      UniqueUsers = dcount(SyslogMessage)
      by bin(TimeGenerated, 1h)
  | order by TimeGenerated asc
  """

  ssh_response = logs_client.query_workspace(
    workspace_id=WORKSPACE_ID,
    query=ssh_query,
    timespan=timedelta(days=1)
  )

  ssh_rows = []
  for table in ssh_response.tables:
    for row in table.rows:
      ssh_rows.append(dict(zip(table.columns, row)))

  ssh_df = pd.DataFrame(ssh_rows) if ssh_rows else pd.DataFrame()
  print(f"SSH data: {len(ssh_df)} rows")

except Exception as e:
  print(f"Log Analytics error: {e}")
  ssh_df = pd.DataFrame()

# ============================================
# CONNECT TO SQL
# ============================================
conn = pyodbc.connect(
  f'DRIVER={{ODBC Driver 17 for SQL Server}};'
  f'SERVER={SQL_SERVER};DATABASE={SQL_DB};'
  f'UID={SQL_USER};PWD={SQL_PASS};'
  f'Encrypt=yes;TrustServerCertificate=no'
)
cursor = conn.cursor()

# Create MLAnomalies table
cursor.execute("""
  IF NOT EXISTS (
    SELECT * FROM sysobjects
    WHERE name='MLAnomalies' AND xtype='U'
  )
  CREATE TABLE MLAnomalies (
    id            INT IDENTITY(1,1) PRIMARY KEY,
    detected_at   DATETIME DEFAULT GETDATE(),
    time_window   DATETIME,
    anomaly_type  VARCHAR(50),
    event_count   INT,
    unique_ips    INT,
    anomaly_score FLOAT,
    confidence    FLOAT,
    model_used    VARCHAR(50),
    description   VARCHAR(1000),
    raw_features  VARCHAR(500)
  )
""")
conn.commit()

# Read from SQL
sql_df = pd.read_sql("""
  SELECT
    CAST(attack_date AS DATETIME) as TimeGenerated,
    COUNT(*) as TotalAttacks,
    COUNT(DISTINCT attacker_ip) as UniqueIPs,
    SUM(CASE WHEN attack_type='SQLi' THEN 1 ELSE 0 END) as SQLi,
    SUM(CASE WHEN attack_type='XSS' THEN 1 ELSE 0 END) as XSS,
    SUM(CASE WHEN attack_type='Botnet' THEN 1 ELSE 0 END) as Botnet,
    SUM(CASE WHEN attack_type='BruteForce' THEN 1 ELSE 0 END) as BruteForce
  FROM WebAttacks
  GROUP BY attack_date
  ORDER BY attack_date
""", conn)

print(f"SQL data: {len(sql_df)} rows")
anomalies_found = []

# ============================================
# MODEL 1 - ISOLATION FOREST ON SSH
# Detects unusual SSH attack spikes
# ============================================
if not ssh_df.empty and len(ssh_df) > 5:
  try:
    features = ssh_df[['SSHAttempts','UniqueIPs','UniqueUsers']].fillna(0)
    scaler   = StandardScaler()
    scaled   = scaler.fit_transform(features)

    model = IsolationForest(contamination=0.1, random_state=42, n_estimators=100)
    ssh_df['anomaly_score'] = model.fit_predict(scaled)
    ssh_df['anomaly_raw']   = model.score_samples(scaled)
    ssh_df['is_anomaly']    = ssh_df['anomaly_score'] == -1

    joblib.dump(model, f"{MODEL_PATH}/iso_forest_ssh.pkl")

    for _, row in ssh_df[ssh_df['is_anomaly']].iterrows():
      anomalies_found.append({
        'time_window' : row.get('TimeGenerated', datetime.now()),
        'anomaly_type': 'SSH_Anomaly',
        'event_count' : int(row.get('SSHAttempts', 0)),
        'unique_ips'  : int(row.get('UniqueIPs', 0)),
        'anomaly_score': float(row.get('anomaly_raw', 0)),
        'confidence'  : 0.9,
        'model_used'  : 'IsolationForest',
        'description' : f"Unusual SSH: {int(row.get('SSHAttempts',0))} attempts from {int(row.get('UniqueIPs',0))} IPs",
        'raw_features': str({'SSHAttempts': int(row.get('SSHAttempts',0)), 'UniqueIPs': int(row.get('UniqueIPs',0))})
      })
    print(f"SSH anomalies: {len(ssh_df[ssh_df['is_anomaly']])}")
  except Exception as e:
    print(f"SSH model error: {e}")

# ============================================
# MODEL 2 - ISOLATION FOREST ON WEB ATTACKS
# Detects unusual web attack patterns
# ============================================
if not sql_df.empty and len(sql_df) > 5:
  try:
    features = sql_df[['TotalAttacks','UniqueIPs','SQLi','XSS','Botnet','BruteForce']].fillna(0)
    scaler   = StandardScaler()
    scaled   = scaler.fit_transform(features)

    model = IsolationForest(contamination=0.1, random_state=42, n_estimators=100)
    sql_df['anomaly_score'] = model.fit_predict(scaled)
    sql_df['anomaly_raw']   = model.score_samples(scaled)
    sql_df['is_anomaly']    = sql_df['anomaly_score'] == -1

    joblib.dump(model, f"{MODEL_PATH}/iso_forest_web.pkl")

    for _, row in sql_df[sql_df['is_anomaly']].iterrows():
      anomalies_found.append({
        'time_window' : row.get('TimeGenerated', datetime.now()),
        'anomaly_type': 'Web_Anomaly',
        'event_count' : int(row.get('TotalAttacks', 0)),
        'unique_ips'  : int(row.get('UniqueIPs', 0)),
        'anomaly_score': float(row.get('anomaly_raw', 0)),
        'confidence'  : 0.85,
        'model_used'  : 'IsolationForest',
        'description' : f"Unusual web: {int(row.get('TotalAttacks',0))} attacks, {int(row.get('SQLi',0))} SQLi, {int(row.get('XSS',0))} XSS",
        'raw_features': str({'TotalAttacks': int(row.get('TotalAttacks',0)), 'SQLi': int(row.get('SQLi',0))})
      })
    print(f"Web anomalies: {len(sql_df[sql_df['is_anomaly']])}")
  except Exception as e:
    print(f"Web model error: {e}")

# ============================================
# MODEL 3 - DBSCAN CLUSTERING
# Detects isolated attack campaigns
# ============================================
if not sql_df.empty and len(sql_df) > 10:
  try:
    features = sql_df[['TotalAttacks','UniqueIPs','SQLi','XSS']].fillna(0)
    scaler   = StandardScaler()
    scaled   = scaler.fit_transform(features)

    dbscan = DBSCAN(eps=0.5, min_samples=2)
    sql_df['cluster'] = dbscan.fit_predict(scaled)

    for _, row in sql_df[sql_df['cluster'] == -1].iterrows():
      anomalies_found.append({
        'time_window' : row.get('TimeGenerated', datetime.now()),
        'anomaly_type': 'Outlier_Campaign',
        'event_count' : int(row.get('TotalAttacks', 0)),
        'unique_ips'  : int(row.get('UniqueIPs', 0)),
        'anomaly_score': -1.0,
        'confidence'  : 0.75,
        'model_used'  : 'DBSCAN',
        'description' : f"Isolated campaign: {int(row.get('TotalAttacks',0))} attacks not matching known patterns",
        'raw_features': str({'TotalAttacks': int(row.get('TotalAttacks',0)), 'UniqueIPs': int(row.get('UniqueIPs',0))})
      })
    print(f"DBSCAN outliers: {len(sql_df[sql_df['cluster'] == -1])}")
  except Exception as e:
    print(f"DBSCAN error: {e}")

# ============================================
# SAVE ANOMALIES TO SQL
# ============================================
for anomaly in anomalies_found:
  cursor.execute("""
    INSERT INTO MLAnomalies
      (time_window, anomaly_type, event_count, unique_ips,
       anomaly_score, confidence, model_used, description, raw_features)
    VALUES (?,?,?,?,?,?,?,?,?)
  """,
    anomaly['time_window'],
    anomaly['anomaly_type'],
    anomaly['event_count'],
    anomaly['unique_ips'],
    anomaly['anomaly_score'],
    anomaly['confidence'],
    anomaly['model_used'],
    anomaly['description'][:1000],
    anomaly['raw_features'][:500]
  )

conn.commit()
conn.close()
print(f"[{datetime.now()}] Done! Saved {len(anomalies_found)} anomalies ✅")
PYTHON

chmod +x /home/adminuser/ml_anomaly_detection.py
chown adminuser:adminuser /home/adminuser/ml_anomaly_detection.py

mkdir -p /home/adminuser/models

# Run every hour
echo "0 * * * * root python3 /home/adminuser/ml_anomaly_detection.py >> /var/log/ml_anomaly.log 2>&1" >> /etc/crontab

echo "VM2 ML Setup complete! ✅" >> /var/log/setup.log
EOF
)
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