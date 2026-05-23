#!/bin/bash
# ============================================
# LAYER 1: PROVISIONING ONLY
# Runs once via cloud-init
# No secrets, no network dependencies
# No runtime initialization
# ============================================
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
KV_URI="${1:-}"  # Key Vault URI passed as first argument

# Structured logging helper
log() {
    echo "$(date -Iseconds) [bootstrap] [$1] $2" | \
        tee -a /var/log/aitdr-bootstrap.log | \
        systemd-cat -t aitdr-bootstrap -p "$1"
}

log info "=== AITDR Bootstrap Layer 1: Provisioning ==="

# ============================================
# DISABLE AUTOMATIC UPDATES (PREVENT LOCKS)
# ============================================
log info "Stopping automatic apt services..."
systemctl stop apt-daily.service || true
systemctl stop apt-daily.timer || true
systemctl stop apt-daily-upgrade.service || true
systemctl stop apt-daily-upgrade.timer || true
systemctl stop unattended-upgrades.service || true

# Kill any stuck apt/dpkg processes
log info "Clearing any existing apt/dpkg locks..."
pkill -9 apt || true
pkill -9 dpkg || true
rm -f /var/lib/dpkg/lock-frontend
rm -f /var/lib/dpkg/lock
rm -f /var/lib/apt/lists/lock
dpkg --configure -a || true
wait_for_apt() {
    local max=600  # 10 minutes
    local count=0
    log info "Checking for apt lock..."
    while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || fuser /var/lib/apt/lists/lock >/dev/null 2>&1 || fuser /var/lib/dpkg/lock >/dev/null 2>&1; do
        if [ $count -ge $max ]; then
            log err "apt lock timeout after $max seconds. Forcing unlock..."
            rm -f /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/lib/apt/lists/lock
            break
        fi
        log warning "apt locked, waiting (attempt $((count/5 + 1)))..."
        sleep 5; count=$((count+5))
    done
    log info "apt is now unlocked."
}

wait_for_apt
dpkg --configure -a
apt-get install -f -y

# ============================================
# SYSTEM PACKAGES
# ============================================
log info "Installing system packages..."
wait_for_apt
apt-get update -y
wait_for_apt
apt-get install -y \
    software-properties-common \
    fail2ban \
    iptables-persistent \
    rkhunter \
    curl \
    python3-pip \
    python3-venv \
    python3-distutils \
    unixodbc-dev \
    jq \
    gnupg \
    ca-certificates \
    lsb-release

# ============================================
# ADMINUSER
# ============================================
if ! id "adminuser" &>/dev/null; then
    useradd -m -s /bin/bash adminuser
fi
mkdir -p /home/adminuser/.ssh
chown -R adminuser:adminuser /home/adminuser/.ssh
chmod 700 /home/adminuser/.ssh

# ============================================
# EXECUTE ISOLATED INSTALLERS
# ============================================
log info "Running Docker CE installer..."
bash /var/lib/aitdr/install-docker.sh

log info "Running Suricata installer..."
bash /var/lib/aitdr/install-suricata.sh

# ============================================
# PYTHON PACKAGES (Virtual Environment)
# ============================================
log info "Setting up Python virtual environment..."
rm -rf /opt/aitdr-venv
python3 -m venv /opt/aitdr-venv
/opt/aitdr-venv/bin/pip install --upgrade pip
/opt/aitdr-venv/bin/pip install --quiet pyodbc azure-identity azure-keyvault-secrets

# ============================================
# AZURE CLI
# ============================================
if ! command -v az >/dev/null 2>&1; then
    log info "Installing Azure CLI..."
    curl -fsSL https://aka.ms/InstallAzureCLIDeb | bash
fi

# ============================================
# ODBC
# ============================================
if ! dpkg -s msodbcsql17 >/dev/null 2>&1; then
    log info "Installing ODBC driver..."
    curl -fsSL https://packages.microsoft.com/keys/microsoft.asc | \
        gpg --dearmor > /etc/apt/trusted.gpg.d/microsoft.gpg
    curl -fsS "https://packages.microsoft.com/config/ubuntu/$(lsb_release -rs)/prod.list" \
        > /etc/apt/sources.list.d/mssql-release.list
    wait_for_apt
    apt-get update -y
    wait_for_apt
    ACCEPT_EULA=Y apt-get install -y msodbcsql17
fi

# ============================================
# SSH HARDENING
# ============================================
log info "Applying SSH hardening..."
mkdir -p /etc/ssh/sshd_config.d/
cat > /etc/ssh/sshd_config.d/99-aitdr.conf << 'EOF'
PermitRootLogin no
PasswordAuthentication no
MaxAuthTries 3
X11Forwarding no
AllowTcpForwarding no
ChallengeResponseAuthentication no
EOF

if sshd -t -f /etc/ssh/sshd_config 2>/dev/null; then
    systemctl restart ssh 2>/dev/null || systemctl restart sshd
else
    log err "SSH config invalid - removing hardening"
    rm -f /etc/ssh/sshd_config.d/99-aitdr.conf
fi

# ============================================
# FAIL2BAN
# ============================================
log info "Configuring fail2ban..."
cat > /etc/fail2ban/jail.local << 'EOF'
[sshd]
enabled  = true
port     = 22
maxretry = 3
bantime  = 3600
findtime = 600
backend  = systemd
EOF
systemctl enable fail2ban
systemctl restart fail2ban

# ============================================
# IPTABLES
# ============================================
log info "Configuring iptables..."
iptables -I DOCKER-USER -d 169.254.169.254 -j DROP 2>/dev/null || true
netfilter-persistent save 2>/dev/null || true

# ============================================
# GENERATE SSL CERTIFICATE
# ============================================
log info "Generating self-signed SSL certificate for honeypot..."
mkdir -p /home/adminuser/ssl
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /home/adminuser/ssl/honeypot.key \
    -out /home/adminuser/ssl/honeypot.crt \
    -subj "/C=US/ST=State/L=City/O=AITDR/CN=honeypot.local"
chmod 600 /home/adminuser/ssl/honeypot.key
chmod 644 /home/adminuser/ssl/honeypot.crt
chown -R adminuser:adminuser /home/adminuser/ssl

# ============================================
# COPY RUNTIME SCRIPTS
# ============================================
log info "Installing runtime scripts..."
cp /var/lib/aitdr/collect-logs.sh /home/adminuser/collect-logs.sh
cp /var/lib/aitdr/parse_logs.py   /home/adminuser/parse_logs.py
cp /var/lib/aitdr/parse_suricata.py /home/adminuser/parse_suricata.py
cp /var/lib/aitdr/init_db.py       /home/adminuser/init_db.py
cp /var/lib/aitdr/create_tables.sql /home/adminuser/create_tables.sql
cp /var/lib/aitdr/docker-compose.yml /home/adminuser/docker-compose.yml
cp /var/lib/aitdr/nginx.conf       /home/adminuser/nginx.conf

# aitdr-init.sh is already copied by the previous block, but let's ensure consistency
cp /var/lib/aitdr/aitdr-init.sh /home/adminuser/aitdr-init.sh
# Inject the Key Vault URI into the script
if [ -n "$KV_URI" ]; then
    sed -i "s|__KEY_VAULT_URI__|${KV_URI}|g" /home/adminuser/aitdr-init.sh
fi

chmod 750 /home/adminuser/collect-logs.sh
chmod 750 /home/adminuser/parse_logs.py
chmod 750 /home/adminuser/parse_suricata.py
chmod 750 /home/adminuser/init_db.py
chmod 644 /home/adminuser/create_tables.sql
chmod 644 /home/adminuser/docker-compose.yml
chmod 644 /home/adminuser/nginx.conf

chown adminuser:adminuser \
    /home/adminuser/collect-logs.sh \
    /home/adminuser/parse_logs.py \
    /home/adminuser/parse_suricata.py \
    /home/adminuser/init_db.py \
    /home/adminuser/create_tables.sql \
    /home/adminuser/docker-compose.yml \
    /home/adminuser/nginx.conf


# ============================================
# INSTALL SYSTEMD UNITS
# ============================================
log info "Installing systemd units..."
cp /var/lib/aitdr/aitdr-init.service     /etc/systemd/system/
cp /var/lib/aitdr/aitdr-collector.service /etc/systemd/system/
cp /var/lib/aitdr/aitdr-collector.timer   /etc/systemd/system/
cp /var/lib/aitdr/aitdr-suricata.service  /etc/systemd/system/
cp /var/lib/aitdr/aitdr-suricata.timer    /etc/systemd/system/

systemctl daemon-reload
systemctl enable aitdr-init.service
systemctl enable aitdr-collector.timer
systemctl enable aitdr-suricata.timer

systemctl start aitdr-init.service || {
    log err "aitdr-init.service failed to start. Checking status..."
    systemctl status aitdr-init.service | tee -a /var/log/aitdr-bootstrap.log
}
systemctl start aitdr-collector.timer
systemctl start aitdr-suricata.timer

apt-get clean
log info "=== Layer 1 Provisioning complete ==="
log info "aitdr-init.service will run on next boot to fetch secrets"