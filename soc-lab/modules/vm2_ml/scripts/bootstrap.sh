#!/bin/bash
# ============================================
# BOOTSTRAP: VM2 ML ANALYSIS
# ============================================
export DEBIAN_FRONTEND=noninteractive
set -e  # Crash immediately if any command fails

echo "Stopping background auto-updaters to prevent apt locks..."
systemctl stop unattended-upgrades apt-daily.service apt-daily-upgrade.service || true

# Wait for any lingering APT/DPKG processes to finish
while pgrep -f apt >/dev/null 2>&1 || pgrep -f dpkg >/dev/null 2>&1; do
  echo "Waiting for apt..."
  sleep 5
done

# Fix any broken packages
sudo dpkg --configure -a

# Install base packages
apt-get update -y
apt-get install -y python3-pip python3-dev unixodbc-dev curl git

# Install ODBC Driver 17 for SQL Server
curl https://packages.microsoft.com/keys/microsoft.asc | apt-key add -
curl https://packages.microsoft.com/config/ubuntu/18.04/prod.list > /etc/apt/sources.list.d/mssql-release.list
apt-get update -y
ACCEPT_EULA=Y apt-get install -y msodbcsql17

# Install ML Libraries
pip3 install scikit-learn pandas numpy pyodbc joblib

# Setup Directories
mkdir -p /var/lib/aitdr/models
chown root:root /var/lib/aitdr/models

# Setup Cron Job (Run ML analysis every hour)
echo "0 * * * * root python3 /var/lib/aitdr/ml_anomaly_detection.py >> /var/log/ml_anomaly.log 2>&1" >> /etc/crontab

echo "VM2 Bootstrap complete! ✅" >> /var/log/setup.log
