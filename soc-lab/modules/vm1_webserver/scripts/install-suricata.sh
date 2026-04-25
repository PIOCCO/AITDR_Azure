#!/bin/bash
# ============================================
# LAYER 1c: SURICATA IDS INSTALLATION
# Optimized for Ubuntu 18.04 LTS
# ============================================
set -euo pipefail

log() { echo "$(date -Iseconds) [suricata-install] $1" | tee -a /var/log/aitdr-bootstrap.log; }

wait_for_apt() {
    local max=600
    local count=0
    while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || fuser /var/lib/apt/lists/lock >/dev/null 2>&1 || fuser /var/lib/dpkg/lock >/dev/null 2>&1; do
        if [ $count -ge $max ]; then
            log "WARNING: apt lock timeout. Forcing unlock..."
            rm -f /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/lib/apt/lists/lock
            break
        fi
        log "WARNING: apt locked, waiting..."
        sleep 5; count=$((count+5))
    done
}

log "Installing Suricata dependencies..."
wait_for_apt
apt-get update -y
wait_for_apt
apt-get install -y software-properties-common

log "Adding Suricata PPA..."
wait_for_apt
add-apt-repository -y ppa:oisf/suricata-stable
wait_for_apt
apt-get update -y

log "Installing Suricata..."
wait_for_apt
apt-get install -y suricata jq

log "Configuring Suricata..."
# Basic configuration to listen on eth0
if [ -f /etc/suricata/suricata.yaml ]; then
    sed -i 's/interface: eth0/interface: eth0/g' /etc/suricata/suricata.yaml
fi

# Enable and start
systemctl enable suricata
systemctl start suricata

log "Suricata installation complete"
