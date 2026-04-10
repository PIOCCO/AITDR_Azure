# ============================================
# MODULE: VM1 WEB SERVER + JIT ACCESS
# Ubuntu VM with DVWA via Docker
# JIT protects SSH - no open ports by default
# ============================================

variable "resource_group_name" {}
variable "location" {}
variable "dmz_subnet_id" {}
variable "ssh_public_key" {}
variable "storage_account_name" {}
variable "sql_server_fqdn" {}
variable "sql_admin_password" {}
variable "admin_username" {
  default = "adminuser"
}

# ============================================
# PUBLIC IP
# ============================================
resource "azurerm_public_ip" "vm1_pip" {
  name                = "VM1-WebServer-PIP"
  location            = var.location
  resource_group_name = var.resource_group_name
  allocation_method   = "Static"
  sku                 = "Standard"
}

# ============================================
# NETWORK INTERFACE
# ============================================
resource "azurerm_network_interface" "vm1_nic" {
  name                = "VM1-WebServer-NIC"
  location            = var.location
  resource_group_name = var.resource_group_name

  ip_configuration {
    name                          = "vm1-ip-config"
    subnet_id                     = var.dmz_subnet_id
    private_ip_address_allocation = "Static"
    private_ip_address            = "10.10.1.10"
    public_ip_address_id          = azurerm_public_ip.vm1_pip.id
  }
}

# ============================================
# Azure Monitor Agent (AMA)
# ============================================
resource "azurerm_virtual_machine_extension" "ama" {
  name                       = "AzureMonitorLinuxAgent"
  virtual_machine_id         = azurerm_linux_virtual_machine.vm1_webserver.id
  publisher                  = "Microsoft.Azure.Monitor"
  type                       = "AzureMonitorLinuxAgent"
  type_handler_version       = "1.0"
  auto_upgrade_minor_version = true
  depends_on = [azurerm_linux_virtual_machine.vm1_webserver]
}

# ============================================
# VM1 - UBUNTU WEB SERVER
# ============================================
resource "azurerm_linux_virtual_machine" "vm1_webserver" {
  name                            = "VM1-WebServer"
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
    azurerm_network_interface.vm1_nic.id
  ]

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "UbuntuServer"
    sku       = "18.04-LTS"
    version   = "latest"
  }

  identity {
    type = "SystemAssigned"
  }

  # ============================================
  # EVERYTHING IN custom_data - Runs once on creation
  # ============================================
  custom_data = base64encode(<<EOF
#!/bin/bash

export DEBIAN_FRONTEND=noninteractive

# Fix any broken packages first
sudo dpkg --configure -a
sudo apt-get install -f -y

# Wait for apt lock
while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; do
  sleep 10
done

# ============================================
# INSTALL ALL PACKAGES
# ============================================
apt-get update -y
apt-get install -y \
  docker.io \
  docker-compose \
  fail2ban \
  iptables-persistent \
  rkhunter \
  curl \
  python3-pip \
  unixodbc-dev

# ============================================
# INSTALL ODBC DRIVER FOR SQL SERVER
# ============================================
curl https://packages.microsoft.com/keys/microsoft.asc | apt-key add -
curl https://packages.microsoft.com/config/ubuntu/18.04/prod.list > /etc/apt/sources.list.d/mssql-release.list
apt-get update -y
ACCEPT_EULA=Y apt-get install -y msodbcsql17
pip3 install pyodbc

# ============================================
# INSTALL SURICATA IDS/IPS
# ============================================
add-apt-repository -y ppa:oisf/suricata-stable
apt-get update -y
apt-get install -y suricata suricata-update
suricata-update
systemctl enable suricata
systemctl start suricata

# ============================================
# INSTALL AZURE CLI
# ============================================
curl -sL https://aka.ms/InstallAzureCLIDeb | bash


# ============================================
# START DOCKER
# ============================================
systemctl enable docker
systemctl start docker
usermod -aG docker adminuser

# ============================================
# CREATE DOCKER-COMPOSE
# ============================================
cat > /home/adminuser/docker-compose.yml << 'DOCKEREOF'
version: '2.2'
services:
  dvwa:
    image: vulnerables/web-dvwa
    ports:
      - "80:80"
    restart: always
    depends_on:
      - mysql
    mem_limit: 512m
    cpus: 0.5
  mysql:
    image: mysql:5.7
    environment:
      MYSQL_ROOT_PASSWORD: dvwa123
      MYSQL_DATABASE: dvwa
      MYSQL_USER: dvwa
      MYSQL_PASSWORD: dvwa123
    restart: always
    mem_limit: 512m
    cpus: 0.5
    volumes:
      - mysql_data:/var/lib/mysql
volumes:
  mysql_data:
DOCKEREOF

# Start DVWA
cd /home/adminuser
docker-compose up -d

# ============================================
# SECURITY - Block Azure metadata from containers
# ============================================
iptables -I DOCKER-USER -d 169.254.169.254 -j DROP
netfilter-persistent save

# ============================================
# CONFIGURE FAIL2BAN
# ============================================
cat > /etc/fail2ban/jail.local << 'FAIL2BAN'
[sshd]
enabled  = true
port     = 22
maxretry = 3
bantime  = 3600
findtime = 600
FAIL2BAN
systemctl enable fail2ban
systemctl restart fail2ban

# ============================================
# HARDEN SSH
# ============================================
sed -i 's/#MaxAuthTries 6/MaxAuthTries 3/' /etc/ssh/sshd_config
sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config
systemctl restart sshd

# ============================================
# FILE PERMISSIONS
# ============================================
chmod 700 /home/adminuser/.ssh
chmod 600 /home/adminuser/.ssh/authorized_keys 2>/dev/null || true

# ============================================
# CREATE LOG PARSER SCRIPT
# Reads apache logs and inserts into SQL
# ============================================
cat > /home/adminuser/parse_logs.py << 'PYTHON'
import pyodbc
from datetime import datetime

SQL_SERVER = "PLACEHOLDER_SQL_SERVER"
SQL_DB     = "AttackLogsDB"
SQL_USER   = "sqladmin"
SQL_PASS   = "PLACEHOLDER_SQL_PASS"

# Connect to SQL
conn = pyodbc.connect(
  f'DRIVER={{ODBC Driver 17 for SQL Server}};'
  f'SERVER={SQL_SERVER};'
  f'DATABASE={SQL_DB};'
  f'UID={SQL_USER};'
  f'PWD={SQL_PASS};'
  f'Encrypt=yes;TrustServerCertificate=no'
)
cursor = conn.cursor()

# Parse apache access log
web_count  = 0
bot_count  = 0
sqli_count = 0
xss_count  = 0

with open('/tmp/apache_access.log') as f:
  for line in f:
    parts = line.split()
    if len(parts) < 9:
      continue

    ip         = parts[0]
    method     = parts[5].strip('"')
    url        = parts[6]
    status     = parts[8]
    user_agent = ' '.join(parts[11:]).strip('"') if len(parts) > 11 else ''

    try:
      status_code = int(status)
    except:
      continue

    # Detect attack type
    url_lower = url.lower()
    if any(x in url_lower for x in ['select', 'union', 'insert', 'drop', 'exec']):
      attack_type = 'SQLi'
      sqli_count += 1
    elif any(x in url_lower for x in ['script', 'alert', 'onerror', 'onload']):
      attack_type = 'XSS'
      xss_count += 1
    elif '../' in url:
      attack_type = 'PathTraversal'
    elif 'mozi' in url_lower or 'setup.cgi' in url_lower:
      attack_type = 'Botnet'
      bot_count += 1
    elif method == 'POST':
      attack_type = 'BruteForce'
    else:
      attack_type = 'Scan'

    # Insert into WebAttacks
    cursor.execute("""
      INSERT INTO WebAttacks
        (attack_date, attack_time, attacker_ip, attack_type,
         url_path, http_method, status_code, user_agent)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """,
      datetime.now().date(),
      datetime.now(),
      ip,
      attack_type,
      url[:500],
      method,
      status_code,
      user_agent[:500]
    )
    web_count += 1

# Parse SSH auth log
ssh_count = 0
with open('/var/log/auth.log') as f:
  for line in f:
    if 'Invalid user' in line or 'Connection closed by invalid' in line:
      parts = line.split()
      try:
        ip = parts[9] if 'Invalid user' in line else parts[7]
        username = parts[7] if 'Invalid user' in line else 'unknown'
        cursor.execute("""
          INSERT INTO SSHAttacks
            (attack_date, attack_time, attacker_ip, username_tried, attack_type)
          VALUES (?, ?, ?, ?, ?)
        """,
          datetime.now().date(),
          datetime.now(),
          ip,
          username,
          'InvalidUser'
        )
        ssh_count += 1
      except:
        continue

# Insert daily summary
cursor.execute("""
  MERGE DailySummary AS target
  USING (SELECT ? AS summary_date) AS source
  ON target.summary_date = source.summary_date
  WHEN MATCHED THEN
    UPDATE SET
      total_web_attacks = ?,
      total_ssh_attacks = ?,
      total_bot_scans   = ?,
      sqli_attempts     = ?,
      xss_attempts      = ?
  WHEN NOT MATCHED THEN
    INSERT (summary_date, total_web_attacks, total_ssh_attacks,
            total_bot_scans, sqli_attempts, xss_attempts)
    VALUES (?, ?, ?, ?, ?, ?);
""",
  datetime.now().date(),
  web_count, ssh_count, bot_count, sqli_count, xss_count,
  datetime.now().date(),
  web_count, ssh_count, bot_count, sqli_count, xss_count
)

conn.commit()
conn.close()
print(f"Done: {web_count} web, {ssh_count} SSH attacks inserted ✅")
PYTHON

# Replace placeholders with real values from Terraform
sed -i "s/PLACEHOLDER_SQL_SERVER/${var.sql_server_fqdn}/g" /home/adminuser/parse_logs.py
sed -i "s/PLACEHOLDER_SQL_PASS/${var.sql_admin_password}/g" /home/adminuser/parse_logs.py
chmod +x /home/adminuser/parse_logs.py

# ============================================
# CREATE Suricata Log Parser Script
# ============================================

cat > /home/adminuser/parse_suricata.py << 'PYTHON'
#!/usr/bin/env python3
import json
import pyodbc
from datetime import datetime
import os

SQL_SERVER  = "PLACEHOLDER_SQL_SERVER"
SQL_DB      = "AttackLogsDB"
SQL_USER    = "sqladmin"
SQL_PASS    = "PLACEHOLDER_SQL_PASS"
EVE_LOG     = "/var/log/suricata/eve.json"
OFFSET_FILE = "/home/adminuser/suricata_offset.txt"

conn = pyodbc.connect(
    f'DRIVER={{ODBC Driver 17 for SQL Server}};'
    f'SERVER={SQL_SERVER};DATABASE={SQL_DB};'
    f'UID={SQL_USER};PWD={SQL_PASS};'
    f'Encrypt=yes;TrustServerCertificate=no'
)
cursor = conn.cursor()

offset = 0
if os.path.exists(OFFSET_FILE):
    with open(OFFSET_FILE) as f:
        offset = int(f.read().strip() or 0)

inserted = 0

with open(EVE_LOG) as f:
    f.seek(offset)
    for line in f:
        try:
            event      = json.loads(line.strip())
            src_ip     = event.get('src_ip', '')
            dest_ip    = event.get('dest_ip', '')
            src_port   = event.get('src_port', 0)
            dest_port  = event.get('dest_port', 0)
            protocol   = event.get('proto', '')
            event_type = event.get('event_type', '')

            try:
                ts = datetime.strptime(event.get('timestamp','')[:19],'%Y-%m-%dT%H:%M:%S')
            except:
                ts = datetime.now()

            alert_sig = alert_sev = http_url = http_method = ''
            http_host = http_ua = http_body = payload = ''
            packet_data = dns_query = tls_sni = ''
            bytes_in = bytes_out = 0

            if event_type == 'alert':
                a = event.get('alert', {})
                alert_sig   = a.get('signature', '')[:500]
                alert_sev   = str(a.get('severity', ''))
                payload     = event.get('payload_printable', '')[:4000]
                packet_data = event.get('packet', '')[:4000]
            elif event_type == 'http':
                h = event.get('http', {})
                http_url    = h.get('url', '')[:1000]
                http_method = h.get('http_method', '')[:10]
                http_host   = h.get('hostname', '')[:200]
                http_ua     = h.get('http_user_agent', '')[:500]
                http_body   = h.get('http_request_body_printable', '')[:4000]
            elif event_type == 'flow':
                fl = event.get('flow', {})
                bytes_in  = fl.get('bytes_toclient', 0)
                bytes_out = fl.get('bytes_toserver', 0)
            elif event_type == 'dns':
                dns_query = event.get('dns', {}).get('rrname', '')[:500]
            elif event_type == 'tls':
                tls_sni = event.get('tls', {}).get('sni', '')[:200]

            cursor.execute("""
                INSERT INTO PacketLogs (
                    timestamp,src_ip,dest_ip,src_port,dest_port,
                    protocol,alert_signature,alert_severity,
                    http_url,http_method,http_host,http_user_agent,
                    http_body,payload,packet_data,
                    flow_bytes_in,flow_bytes_out,
                    dns_query,tls_sni,raw_json
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
                ts,src_ip,dest_ip,src_port,dest_port,
                protocol,alert_sig,alert_sev,
                http_url,http_method,http_host,http_ua,
                http_body,payload,packet_data,
                bytes_in,bytes_out,
                dns_query,tls_sni,
                line.strip()[:4000]
            )
            inserted += 1
        except:
            continue

    with open(OFFSET_FILE,'w') as of:
        of.write(str(f.tell()))

conn.commit()
conn.close()
print(f"[{datetime.now()}] Inserted {inserted} packet logs ✅")
PYTHON

chmod +x /home/adminuser/parse_suricata.py

sed -i "s/PLACEHOLDER_SQL_SERVER/${var.sql_server_fqdn}/g" /home/adminuser/parse_suricata.py
sed -i "s/PLACEHOLDER_SQL_PASS/${var.sql_admin_password}/g" /home/adminuser/parse_suricata.py

# ============================================
# CREATE LOG COLLECTION SCRIPT
# ============================================
cat > /home/adminuser/collect_logs.sh << 'SCRIPT'
#!/bin/bash

YEAR=$(date +%Y)
MONTH=$(date +%m)
WEEK=$(date +%V)
DAY=$(date +%Y-%m-%d)

mkdir -p /home/adminuser/logs/$YEAR/$MONTH/week-$WEEK/$DAY

DAILY_REPORT="/home/adminuser/logs/$YEAR/$MONTH/week-$WEEK/$DAY/attack_report_$DAY.txt"
STORAGE_ACCOUNT="PLACEHOLDER_STORAGE"
CONTAINER="attack-logs"

DVWA_CONTAINER=$(docker ps --format "{{.Names}}" | grep dvwa | head -1)
docker cp $DVWA_CONTAINER:/var/log/apache2/access.log /tmp/apache_access.log 2>/dev/null
LOG_FILE="/tmp/apache_access.log"

echo "===============================" >> $DAILY_REPORT
echo "REPORT DATE: $DAY" >> $DAILY_REPORT
echo "REPORT TIME: $(date)" >> $DAILY_REPORT
echo "DVWA CONTAINER: $DVWA_CONTAINER" >> $DAILY_REPORT
echo "===============================" >> $DAILY_REPORT

echo "" >> $DAILY_REPORT
echo "===============================" >> $DAILY_REPORT
echo "ALL VISITOR IPs" >> $DAILY_REPORT
echo "===============================" >> $DAILY_REPORT
awk '{print $1}' $LOG_FILE | grep -v "::1" | sort | uniq -c | sort -rn >> $DAILY_REPORT

echo "" >> $DAILY_REPORT
echo "===============================" >> $DAILY_REPORT
echo "PAGES THEY TRIED TO ACCESS" >> $DAILY_REPORT
echo "===============================" >> $DAILY_REPORT
awk '{print $7}' $LOG_FILE | sort | uniq -c | sort -rn >> $DAILY_REPORT

echo "" >> $DAILY_REPORT
echo "===============================" >> $DAILY_REPORT
echo "FILES BOTS TRIED TO FIND 404s" >> $DAILY_REPORT
echo "===============================" >> $DAILY_REPORT
grep "404" $LOG_FILE | awk '{print $7}' | sort | uniq -c | sort -rn >> $DAILY_REPORT

echo "" >> $DAILY_REPORT
echo "===============================" >> $DAILY_REPORT
echo "FAILED ATTEMPTS 404s" >> $DAILY_REPORT
echo "===============================" >> $DAILY_REPORT
grep " 404 " $LOG_FILE | awk '{print $1, $7}' | sort | uniq -c | sort -rn >> $DAILY_REPORT

echo "" >> $DAILY_REPORT
echo "===============================" >> $DAILY_REPORT
echo "POST REQUESTS LOGIN ATTEMPTS" >> $DAILY_REPORT
echo "===============================" >> $DAILY_REPORT
grep "POST" $LOG_FILE | awk '{print $1, $7}' | sort | uniq -c | sort -rn >> $DAILY_REPORT

echo "" >> $DAILY_REPORT
echo "===============================" >> $DAILY_REPORT
echo "BRUTE FORCE LOGIN ATTEMPTS" >> $DAILY_REPORT
echo "===============================" >> $DAILY_REPORT
grep -i "POST.*login" $LOG_FILE | awk '{print $1}' | sort | uniq -c | sort -rn >> $DAILY_REPORT

echo "" >> $DAILY_REPORT
echo "===============================" >> $DAILY_REPORT
echo "SQL INJECTION ATTEMPTS" >> $DAILY_REPORT
echo "===============================" >> $DAILY_REPORT
grep -i "select\|union\|insert\|drop" $LOG_FILE >> $DAILY_REPORT

echo "" >> $DAILY_REPORT
echo "===============================" >> $DAILY_REPORT
echo "PATH TRAVERSAL ATTEMPTS" >> $DAILY_REPORT
echo "===============================" >> $DAILY_REPORT
grep -i "\.\./" $LOG_FILE >> $DAILY_REPORT

echo "" >> $DAILY_REPORT
echo "===============================" >> $DAILY_REPORT
echo "XSS ATTEMPTS" >> $DAILY_REPORT
echo "===============================" >> $DAILY_REPORT
grep -i "script\|alert\|onerror" $LOG_FILE >> $DAILY_REPORT

echo "" >> $DAILY_REPORT
echo "===============================" >> $DAILY_REPORT
echo "BOT SIGNATURES" >> $DAILY_REPORT
echo "===============================" >> $DAILY_REPORT
awk -F'"' '{print $6}' $LOG_FILE | sort | uniq -c | sort -rn >> $DAILY_REPORT

echo "" >> $DAILY_REPORT
echo "===============================" >> $DAILY_REPORT
echo "ATTACK TIMELINE" >> $DAILY_REPORT
echo "===============================" >> $DAILY_REPORT
awk '{print $4}' $LOG_FILE | cut -d: -f1,2 | tr -d '[' | sort | uniq -c >> $DAILY_REPORT

echo "" >> $DAILY_REPORT
echo "===============================" >> $DAILY_REPORT
echo "TOP 10 AGGRESSIVE IPs" >> $DAILY_REPORT
echo "===============================" >> $DAILY_REPORT
awk '{print $1}' $LOG_FILE | grep -v "::1" | sort | uniq -c | sort -rn | head -10 >> $DAILY_REPORT

echo "" >> $DAILY_REPORT
echo "===============================" >> $DAILY_REPORT
echo "SSH FAILED ATTEMPTS" >> $DAILY_REPORT
echo "===============================" >> $DAILY_REPORT
grep "Invalid user" /var/log/auth.log | awk '{print $10}' | sort | uniq -c | sort -rn >> $DAILY_REPORT

echo "" >> $DAILY_REPORT
echo "===============================" >> $DAILY_REPORT
echo "SSH SUCCESSFUL LOGINS" >> $DAILY_REPORT
echo "===============================" >> $DAILY_REPORT
grep "Accepted publickey" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -rn >> $DAILY_REPORT

echo "" >> $DAILY_REPORT
echo "===============================" >> $DAILY_REPORT
echo "DOCKER CONTAINER STATUS" >> $DAILY_REPORT
echo "===============================" >> $DAILY_REPORT
docker ps >> $DAILY_REPORT

az login --identity
az storage blob upload \
  --account-name $STORAGE_ACCOUNT \
  --container-name $CONTAINER \
  --name "$YEAR/$MONTH/week-$WEEK/$DAY/attack_report_$DAY.txt" \
  --file $DAILY_REPORT \
  --auth-mode login \
  --overwrite

# Parse logs into SQL
python3 /home/adminuser/parse_logs.py
SCRIPT

# Replace placeholder with real storage name
sed -i "s/PLACEHOLDER_STORAGE/${var.storage_account_name}/g" /home/adminuser/collect_logs.sh
chmod +x /home/adminuser/collect_logs.sh

# ============================================
# CRON JOB ONLY - No boot service
# ============================================
echo "* * * * * root bash /home/adminuser/collect_logs.sh" >> /etc/crontab
echo "* * * * * root python3 /home/adminuser/parse_suricata.py >> /var/log/suricata_parser.log 2>&1" >> /etc/crontab

systemctl restart rsyslog

echo "Setup complete! ✅" >> /var/log/setup.log
EOF
)
}

# ============================================
# AUTO SHUTDOWN - 11PM every day
# ============================================
resource "azurerm_dev_test_global_vm_shutdown_schedule" "vm1_shutdown" {
  virtual_machine_id    = azurerm_linux_virtual_machine.vm1_webserver.id
  location              = var.location
  enabled               = true
  daily_recurrence_time = "2300"
  timezone              = "UTC"

  notification_settings {
    enabled = false
  }
}

# ============================================
# JIT - Enable Microsoft Defender
# ============================================
resource "azurerm_security_center_subscription_pricing" "vm_defender" {
  tier          = "Standard"
  resource_type = "VirtualMachines"
}

# ============================================
# OUTPUTS
# ============================================
output "vm1_public_ip" {
  value       = azurerm_public_ip.vm1_pip.ip_address
  description = "Visit DVWA at http://<this_ip>/dvwa"
}

output "vm1_private_ip" {
  value = azurerm_network_interface.vm1_nic.private_ip_address
}

output "vm1_id" {
  value = azurerm_linux_virtual_machine.vm1_webserver.id
}

output "vm1_principal_id" {
  value = azurerm_linux_virtual_machine.vm1_webserver.identity[0].principal_id
}
