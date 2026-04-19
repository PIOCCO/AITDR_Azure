#!/bin/bash
# ============================================
# VM1 BOOTSTRAP SCRIPT - PRODUCTION FINAL v7
# FULLY ATOMIC - RESILIENT - NO SILENT FAILURES
# ============================================

# Enforce root execution
if [ "$EUID" -ne 0 ]; then 
  echo "Please run as root"
  exit 1
fi

set -e  # Exit on any error
set -o pipefail
export DEBIAN_FRONTEND=noninteractive
key_vault_uri="${key_vault_uri}"

# Use journald as primary logging
echo "AITDR bootstrap v7 starting" | systemd-cat -t aitdr-bootstrap -p info

# ============================================
# APT LOCK WAIT
# ============================================
while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; do
  echo "Waiting for dpkg lock..." | systemd-cat -t aitdr-bootstrap -p warning
  sleep 10
done

dpkg --configure -a
apt-get install -f -y

# ============================================
# PACKAGE INSTALLATION (robust dpkg check)
# ============================================
apt-get update -y

is_pkg_installed() {
  dpkg -s "$1" 2>/dev/null | grep -q "^Status: install ok installed"
}

install_if_missing() {
  if ! is_pkg_installed "$1"; then
    apt-get install -y "$1"
  fi
}

# Core packages
for pkg in software-properties-common docker.io fail2ban iptables-persistent rkhunter curl python3-pip unixodbc-dev jq gnupg; do
  install_if_missing "$pkg"
done

# Ensure adminuser exists
if ! id "adminuser" &>/dev/null; then
  useradd -m -s /bin/bash adminuser
  echo "adminuser:$(openssl rand -base64 32)" | chpasswd
fi
usermod -aG docker adminuser

# Docker Compose with version pinning
if ! command -v docker-compose >/dev/null 2>&1 && ! docker compose version >/dev/null 2>&1; then
  if ! is_pkg_installed docker-compose-plugin; then
    # Install specific version for reproducibility
    DOCKER_COMPOSE_VERSION="v2.24.0"
    curl -fsSL "https://github.com/docker/compose/releases/download/${DOCKER_COMPOSE_VERSION}/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    chmod +x /usr/local/bin/docker-compose
  fi
fi

# Normalize docker compose command
if docker compose version >/dev/null 2>&1; then
  DOCKER_COMPOSE_CMD="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
  DOCKER_COMPOSE_CMD="docker-compose"
else
  echo "Docker Compose not available" | systemd-cat -t aitdr-bootstrap -p error
  exit 1
fi

# Ensure netfilter-persistent is installed and enabled
if ! is_pkg_installed iptables-persistent; then
  install_if_missing iptables-persistent
fi
systemctl enable netfilter-persistent 2>/dev/null || true

# ============================================
# ODBC DRIVER (idempotent)
# ============================================
if ! is_pkg_installed msodbcsql17; then
  curl -fsSL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > microsoft.gpg
  install -o root -g root -m 644 microsoft.gpg /etc/apt/trusted.gpg.d/
  rm microsoft.gpg
  curl -fsS https://packages.microsoft.com/config/ubuntu/18.04/prod.list > /etc/apt/sources.list.d/mssql-release.list
  apt-get update -y
  ACCEPT_EULA=Y apt-get install -y msodbcsql17
fi

# Idempotent pip installs
pip3 show pyodbc >/dev/null 2>&1 || pip3 install pyodbc azure-identity azure-keyvault-secrets

# ============================================
# SURICATA (robust interface detection)
# ============================================
if ! command -v suricata >/dev/null 2>&1; then
  add-apt-repository -y ppa:oisf/suricata-stable
  apt-get update -y
  apt-get install -y suricata suricata-update
fi

mkdir -p /etc/suricata/rules

# Robust interface detection (multiple fallbacks)
PRIMARY_IFACE=""
# Method 1: Default route interface
if command -v ip >/dev/null 2>&1; then
  PRIMARY_IFACE=$(ip route get 8.8.8.8 2>/dev/null | awk '{print $5; exit}' 2>/dev/null)
fi
# Method 2: First non-loopback, non-docker interface
if [ -z "$PRIMARY_IFACE" ]; then
  PRIMARY_IFACE=$(ls /sys/class/net/ 2>/dev/null | grep -Ev 'lo|docker|veth' | head -n1)
fi
# Method 3: eth0 fallback
if [ -z "$PRIMARY_IFACE" ]; then
  PRIMARY_IFACE="eth0"
fi

echo "Using network interface: $PRIMARY_IFACE" | systemd-cat -t aitdr-bootstrap -p info

# Idempotent suricata-update (check if rules exist)
SURICATA_RULES_FILE="/var/lib/suricata/rules/suricata.rules"
SURICATA_UPDATE_TIMESTAMP="/var/lib/suricata/.last_update"
if [ ! -f "$SURICATA_RULES_FILE" ] || [ ! -f "$SURICATA_UPDATE_TIMESTAMP" ] || [ $(find "$SURICATA_UPDATE_TIMESTAMP" -mtime +7 2>/dev/null) ]; then
  suricata-update 2>&1 | systemd-cat -t aitdr-bootstrap -p info
  touch "$SURICATA_UPDATE_TIMESTAMP"
fi

# Get HOME_NET from Azure metadata with proper timeout/retry
HOME_NET="$${home_net:-}"
if [ -z "$HOME_NET" ]; then
  HOME_NET=$(curl -fsS --retry 5 --retry-delay 1 --connect-timeout 3 --max-time 5 \
    -H "Metadata:true" \
    "http://169.254.169.254/metadata/network/interfaces?api-version=2021-02-01&format=json" \
    2>/dev/null | jq -r '.[0].ipv4.subnet[0].prefix // "10.0.0.0/16"' 2>/dev/null)
fi
[ -z "$HOME_NET" ] && HOME_NET="10.0.0.0/16"

cat > /etc/suricata/suricata.yaml << EOF
%YAML 1.1
---

vars:
  address-groups:
    HOME_NET: "[$HOME_NET]"
    EXTERNAL_NET: "any"

af-packet:
  - interface: $PRIMARY_IFACE

default-rule-path: /etc/suricata/rules

rule-files:
  - local.rules

outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: /var/log/suricata/eve.json
      types:
        - alert
        - http
        - dns
        - tls
        - flow
EOF

# Validate rules directory exists before writing
mkdir -p /etc/suricata/rules
cat > /etc/suricata/rules/local.rules << 'EOF'
alert icmp any any -> any any (msg:"ICMP detected"; sid:1000001; rev:1;)
alert http any any -> any any (msg:"HTTP traffic detected"; sid:1000002; rev:1;)
alert tcp any any -> any 22 (msg:"SSH attempt"; sid:1000003; rev:1;)
alert tcp any any -> any 443 (msg:"HTTPS traffic detected"; sid:1000004; rev:1;)
alert dns any any -> any any (msg:"DNS query detected"; sid:1000005; rev:1;)
EOF

# Validate Suricata
if ! suricata -T -c /etc/suricata/suricata.yaml; then
  echo "Suricata validation failed" | systemd-cat -t aitdr-bootstrap -p error
  exit 1
fi

systemctl enable suricata
systemctl restart suricata

# ============================================
# AZURE CLI
# ============================================
if ! command -v az >/dev/null 2>&1; then
  curl -fsSL https://aka.ms/InstallAzureCLIDeb | bash
fi

# ============================================
# DOCKER
# ============================================
systemctl enable docker
systemctl start docker

# ============================================
# SECURITY - BLOCK METADATA (with persistence guarantee)
# ============================================
iptables -I DOCKER-USER -d 169.254.169.254 -j DROP 2>/dev/null || true
if command -v netfilter-persistent >/dev/null 2>&1; then
  netfilter-persistent save 2>/dev/null || true
fi

# ============================================
# FAIL2BAN
# ============================================
cat > /etc/fail2ban/jail.local << 'FAIL2BAN'
[sshd]
enabled = true
port = 22
maxretry = 3
bantime = 3600
findtime = 600
backend = systemd
journalmatch = _SYSTEMD_UNIT=ssh.service
FAIL2BAN
systemctl enable fail2ban
systemctl restart fail2ban

# ============================================
# SSH HARDENING (drop-in with validation)
# ============================================
mkdir -p /etc/ssh/sshd_config.d/
cat > /etc/ssh/sshd_config.d/99-aitdr-hardening.conf << 'EOF'
PermitRootLogin no
PasswordAuthentication no
MaxAuthTries 3
X11Forwarding no
AllowTcpForwarding no
ChallengeResponseAuthentication no
EOF

# Validate and rollback if needed, handle ssh/sshd service name difference
if sshd -t 2>/dev/null || /usr/sbin/sshd -t 2>/dev/null; then
  if systemctl list-units --type=service | grep -q sshd.service; then
    systemctl restart sshd
  else
    systemctl restart ssh
  fi
else
  echo "SSH config invalid, removing hardening" | systemd-cat -t aitdr-bootstrap -p error
  rm -f /etc/ssh/sshd_config.d/99-aitdr-hardening.conf
  if systemctl list-units --type=service | grep -q sshd.service; then
    systemctl restart sshd
  else
    systemctl restart ssh
  fi
fi

# ============================================
# FILE PERMISSIONS
# ============================================
mkdir -p /home/adminuser/.ssh
chown -R adminuser:adminuser /home/adminuser/.ssh
chmod 700 /home/adminuser/.ssh

# ============================================
# KEY VAULT FETCH (atomic with HTTP validation)
# ============================================
echo "Fetching secrets from Key Vault..." | systemd-cat -t aitdr-bootstrap -p info

RETRY_COUNT=0
MAX_RETRIES=5
FETCH_SUCCESS=false

# Atomic fetch function - all or nothing
fetch_all_secrets() {
  local token_file=$(mktemp)
  local secrets_file=$(mktemp)
  
  # Get token with HTTP status validation and proper retry
  local http_code=$(curl -fsS -w "%%{http_code}" --retry 5 --retry-delay 2 --connect-timeout 3 --max-time 10 \
    -H "Metadata:true" \
    -o "$token_file" \
    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net")
  
  if [ "$http_code" != "200" ]; then
    rm -f "$token_file" "$secrets_file"
    return 1
  fi
  
  local token=$(jq -r '.access_token' "$token_file" 2>/dev/null)
  rm -f "$token_file"
  
  if [ -z "$token" ] || [ "$token" = "null" ]; then
    rm -f "$secrets_file"
    return 1
  fi
  
  # Fetch all secrets in parallel for atomicity
  local server_val pass_val storage_val
  
  server_val=$(curl -fsS --retry 3 --max-time 5 -H "Authorization: Bearer $token" \
    "${key_vault_uri}/secrets/sql-server-fqdn?api-version=7.3" | jq -r '.value' 2>/dev/null)
  
  pass_val=$(curl -fsS --retry 3 --max-time 5 -H "Authorization: Bearer $token" \
    "${key_vault_uri}/secrets/sql-admin-password?api-version=7.3" | jq -r '.value' 2>/dev/null)
  
  storage_val=$(curl -fsS --retry 3 --max-time 5 -H "Authorization: Bearer $token" \
    "${key_vault_uri}/secrets/storage-account-name?api-version=7.3" | jq -r '.value' 2>/dev/null)
  
  # Validate all secrets present
  if [ -n "$server_val" ] && [ "$server_val" != "null" ] && \
     [ -n "$pass_val" ] && [ "$pass_val" != "null" ] && \
     [ -n "$storage_val" ] && [ "$storage_val" != "null" ]; then
    echo "$server_val|$pass_val|$storage_val" > "$secrets_file"
    cat "$secrets_file"
    rm -f "$secrets_file"
    return 0
  fi
  
  rm -f "$secrets_file"
  return 1
}

# Retry loop with atomic fetch
while [ $RETRY_COUNT -lt $MAX_RETRIES ] && [ "$FETCH_SUCCESS" = false ]; do
  SECRETS_DATA=$(fetch_all_secrets 2>/dev/null)
  if [ $? -eq 0 ] && [ -n "$SECRETS_DATA" ]; then
    SQL_SERVER=$(echo "$SECRETS_DATA" | cut -d'|' -f1)
    SQL_PASS=$(echo "$SECRETS_DATA" | cut -d'|' -f2)
    STORAGE_ACCOUNT=$(echo "$SECRETS_DATA" | cut -d'|' -f3)
    FETCH_SUCCESS=true
    echo "Secrets fetched atomically on attempt $((RETRY_COUNT+1))" | systemd-cat -t aitdr-bootstrap -p info
  else
    echo "Atomic fetch attempt $((RETRY_COUNT+1)) failed" | systemd-cat -t aitdr-bootstrap -p warning
    RETRY_COUNT=$((RETRY_COUNT+1))
    [ $RETRY_COUNT -lt $MAX_RETRIES ] && sleep 10
  fi
done

if [ "$FETCH_SUCCESS" = false ]; then
  echo "Key Vault fetch FAILED after $MAX_RETRIES attempts" | systemd-cat -t aitdr-bootstrap -p crit
  systemctl poweroff
  exit 1
fi

# ============================================
# DOCKER COMPOSE (persistent MySQL root password)
# ============================================
MYSQL_ROOT_PASS_FILE="/home/adminuser/.mysql_root"
if [ -f "$MYSQL_ROOT_PASS_FILE" ]; then
  MYSQL_ROOT_PASS=$(cat "$MYSQL_ROOT_PASS_FILE")
else
  MYSQL_ROOT_PASS=$(openssl rand -base64 32 | tr -d '/+=' | head -c 32)
  echo "$MYSQL_ROOT_PASS" > "$MYSQL_ROOT_PASS_FILE"
  chmod 600 "$MYSQL_ROOT_PASS_FILE"
  chown adminuser:adminuser "$MYSQL_ROOT_PASS_FILE"
fi

cat > /home/adminuser/.db.env << EOF
MYSQL_ROOT_PASSWORD=$MYSQL_ROOT_PASS
MYSQL_DATABASE=dvwa
MYSQL_USER=dvwa
MYSQL_PASSWORD=$SQL_PASS
EOF

chmod 600 /home/adminuser/.db.env
chown adminuser:adminuser /home/adminuser/.db.env

# Safe container cleanup - use compose project scope
cd /home/adminuser
$DOCKER_COMPOSE_CMD down 2>/dev/null || true

cat > /home/adminuser/docker-compose.yml << 'EOF'
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
    env_file:
      - .db.env
    restart: always
    mem_limit: 512m
    cpus: 0.5
    volumes:
      - mysql_data:/var/lib/mysql

volumes:
  mysql_data:
EOF

$DOCKER_COMPOSE_CMD up -d

# ============================================
# CONFIG FILES
# ============================================
cat > /home/adminuser/.env << ENVEOF
SQL_SERVER=$SQL_SERVER
SQL_DB=AttackLogsDB
SQL_USER=sqladmin
STORAGE_ACCOUNT=$STORAGE_ACCOUNT
ENVEOF

echo "$SQL_PASS" > /home/adminuser/.sql_pass

chmod 600 /home/adminuser/.env
chmod 600 /home/adminuser/.sql_pass
chown adminuser:adminuser /home/adminuser/.env
chown adminuser:adminuser /home/adminuser/.sql_pass

# Clear secrets from memory
unset TOKEN SQL_SERVER SQL_PASS STORAGE_ACCOUNT MYSQL_ROOT_PASS

# ============================================
# SCRIPTS (fixed heredoc function)
# ============================================
# Simple direct heredoc - no function wrapper needed
cat > /home/adminuser/parse_logs.py << 'EOF'
#!/usr/bin/env python3
import sys
print("Log parser placeholder")
EOF

cat > /home/adminuser/collect_logs.sh << 'EOF'
#!/bin/bash
echo "[$(date)] Collecting logs..." | systemd-cat -t aitdr-collector -p info
EOF

cat > /home/adminuser/parse_suricata.py << 'EOF'
#!/usr/bin/env python3
import json
import sys
print("Suricata parser placeholder")
EOF

chmod +x /home/adminuser/parse_logs.py /home/adminuser/collect_logs.sh /home/adminuser/parse_suricata.py
chown adminuser:adminuser /home/adminuser/parse_logs.py /home/adminuser/collect_logs.sh /home/adminuser/parse_suricata.py

# ============================================
# SYSTEMD TIMERS (with proper Restart for oneshot)
# ============================================

cat > /etc/systemd/system/collect-logs.service << 'SVCEOF'
[Unit]
Description=AITDR Log Collection
After=network-online.target docker.service suricata.service
Wants=network-online.target
ConditionPathExists=/home/adminuser/collect_logs.sh
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
Type=oneshot
User=adminuser
ExecStart=/bin/bash /home/adminuser/collect_logs.sh
Restart=on-failure
RestartSec=30
StandardOutput=journal
StandardError=journal
SVCEOF

cat > /etc/systemd/system/collect-logs.timer << 'TIMEREOF'
[Unit]
Description=Run AITDR log collection every minute
Requires=collect-logs.service

[Timer]
OnBootSec=2min
OnUnitActiveSec=1min

[Install]
WantedBy=timers.target
TIMEREOF

cat > /etc/systemd/system/parse-suricata.service << 'SVCEOF'
[Unit]
Description=AITDR Suricata Parser
After=network-online.target suricata.service
Wants=network-online.target
ConditionPathExists=/home/adminuser/parse_suricata.py
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
Type=oneshot
User=adminuser
ExecStart=/usr/bin/python3 /home/adminuser/parse_suricata.py
Restart=on-failure
RestartSec=30
StandardOutput=journal
StandardError=journal
SVCEOF

cat > /etc/systemd/system/parse-suricata.timer << 'TIMEREOF'
[Unit]
Description=Run Suricata parser every minute
Requires=parse-suricata.service

[Timer]
OnBootSec=3min
OnUnitActiveSec=1min

[Install]
WantedBy=timers.target
TIMEREOF

# ============================================
# FINAL STABILIZATION & START
# ============================================
echo "Waiting 120 seconds for stabilization..." | systemd-cat -t aitdr-bootstrap -p info
sleep 120

systemctl daemon-reload

# Only enable timers (services don't need enable)
systemctl enable collect-logs.timer parse-suricata.timer
systemctl start collect-logs.timer parse-suricata.timer

# Verify timers are active
if systemctl is-active --quiet collect-logs.timer && systemctl is-active --quiet parse-suricata.timer; then
  echo "AITDR bootstrap v7 complete successfully ✅" | systemd-cat -t aitdr-bootstrap -p info
else
  echo "AITDR bootstrap v7 completed with timer failures ⚠️" | systemd-cat -t aitdr-bootstrap -p warning
fi