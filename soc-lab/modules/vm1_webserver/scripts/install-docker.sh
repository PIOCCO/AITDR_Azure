#!/bin/bash
# ============================================
# LAYER 1b: DOCKER CE INSTALLATION
# Isolated failure domain
# ============================================
set -euo pipefail

log() { echo "$(date -Iseconds) [docker-install] $1" | tee -a /var/log/aitdr-bootstrap.log; }

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

# Remove legacy packages
wait_for_apt
for pkg in docker.io docker-doc docker-compose podman-docker containerd runc; do
    apt-get remove -y "$pkg" 2>/dev/null || true
done

# Add Docker official GPG key
mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
    | gpg --dearmor -o /etc/apt/keyrings/docker.gpg

echo "deb [arch=$(dpkg --print-architecture) \
    signed-by=/etc/apt/keyrings/docker.gpg] \
    https://download.docker.com/linux/ubuntu \
    $(lsb_release -cs) stable" \
    > /etc/apt/sources.list.d/docker.list

wait_for_apt
apt-get update -y
wait_for_apt
apt-get install -y \
    docker-ce \
    docker-ce-cli \
    containerd.io \
    docker-compose-plugin

# Validate
docker compose version >/dev/null 2>&1 || {
    log "ERROR: docker compose plugin not functional"
    exit 1
}

usermod -aG docker adminuser

systemctl enable docker
systemctl start docker

# Wait for socket
for i in $(seq 1 10); do
    docker info >/dev/null 2>&1 && break
    [ $i -eq 10 ] && { log "ERROR: Docker socket not ready"; exit 1; }
    sleep 3
done

log "Docker CE installed and ready"