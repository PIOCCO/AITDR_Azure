#!/bin/bash
# ============================================
# LAYER 2: RUNTIME INITIALIZATION
# Runs via systemd after network is ready
# ============================================
set -euo pipefail

# This placeholder will be replaced by bootstrap.sh using sed
KV_URI="__KEY_VAULT_URI__"

log() {
    echo "$(date -Iseconds) [aitdr-init] [$1] $2" | \
        systemd-cat -t aitdr-init -p "$1"
}

log info "=== AITDR Layer 2: Runtime Init ==="

# ============================================
# WAIT FOR IMDS + RBAC PROPAGATION
# ============================================
log info "Waiting for IMDS availability..."
IMDS_READY=false
for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30; do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        --connect-timeout 2 --max-time 3 \
        -H "Metadata:true" \
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01")
    [ "$HTTP_CODE" = "200" ] && { IMDS_READY=true; break; }
    log warning "IMDS not ready (attempt $i/30)"
    sleep 10
done
[ "$IMDS_READY" = false ] && { log err "IMDS unavailable"; exit 1; }

# ============================================
# AZURE LOGIN (MSI)
# ============================================
log info "Authenticating with Managed Identity..."
az login --identity --allow-no-subscriptions >/dev/null 2>&1 || {
    log warning "az login failed, will retry via curl for secrets"
}

# ============================================
# FETCH TOKEN
# ============================================
log info "Fetching managed identity token..."
TOKEN=$(curl -fsS \
    --retry 10 --retry-delay 10 --retry-max-time 180 \
    -H "Metadata:true" \
    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net" \
    | jq -r '.access_token')

if [ -z "$TOKEN" ] || [ "$TOKEN" = "null" ]; then
    log err "Token fetch failed"
    exit 1
fi

# ============================================
# FETCH SECRETS
# ============================================
fetch_secret() {
    local name="$1"
    local value
    value=$(curl -fsS \
        --retry 5 --retry-delay 5 \
        -H "Authorization: Bearer $TOKEN" \
        "${KV_URI}secrets/${name}?api-version=7.3" \
        | jq -r '.value' 2>/dev/null)

    if [ -z "$value" ] || [ "$value" = "null" ]; then
        log err "Failed to fetch secret: $name"
        return 1
    fi
    echo "$value"
}

log info "Fetching secrets from Key Vault..."
SQL_SERVER=$(fetch_secret "sql-server-fqdn")
SQL_PASS=$(fetch_secret "sql-admin-password")
STORAGE_ACCOUNT=$(fetch_secret "storage-account-name")

log info "All secrets fetched successfully"

# ============================================
# WRITE SECURE CONFIG
# ============================================
install -o adminuser -g adminuser -m 600 /dev/null /home/adminuser/.env
cat > /home/adminuser/.env << ENVEOF
SQL_SERVER=${SQL_SERVER}
SQL_DB=AttackLogsDB
SQL_USER=sqladmin
STORAGE_ACCOUNT=${STORAGE_ACCOUNT}
ENVEOF

echo "${SQL_PASS}" > /home/adminuser/.sql_pass
chmod 600 /home/adminuser/.sql_pass
chown adminuser:adminuser /home/adminuser/.sql_pass

# ============================================
# INITIALIZE SQL DATABASE SCHEMA
# ============================================
log info "Initializing SQL database schema..."
/opt/aitdr-venv/bin/python3 /home/adminuser/init_db.py

# ============================================
# GENERATE MYSQL CREDENTIALS
# ============================================
if [ ! -f /home/adminuser/.mysql_root ]; then
    openssl rand -base64 32 | tr -d '/+=' | head -c 32 \
        > /home/adminuser/.mysql_root
    chmod 600 /home/adminuser/.mysql_root
    chown adminuser:adminuser /home/adminuser/.mysql_root
fi
MYSQL_ROOT_PASS=$(cat /home/adminuser/.mysql_root)
DVWA_DB_PASS=$(cat /home/adminuser/.sql_pass)

install -o adminuser -g adminuser -m 600 /dev/null /home/adminuser/.db.env
cat > /home/adminuser/.db.env << ENVEOF
MYSQL_ROOT_PASSWORD=${MYSQL_ROOT_PASS}
MYSQL_DATABASE=dvwa
MYSQL_USER=dvwa
MYSQL_PASSWORD=${DVWA_DB_PASS}
ENVEOF

# ============================================
# DOCKER READINESS
# ============================================
log info "Checking Docker readiness..."
for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30; do
    if docker info >/dev/null 2>&1; then
        log info "Docker is ready"
        break
    fi
    [ $i -eq 30 ] && { log err "Docker failed to start in time"; exit 1; }
    log warning "Waiting for Docker socket... ($i/30)"
    sleep 5
done

# ============================================
# DOCKER COMPOSE
# ============================================
log info "Starting Docker Compose stack..."
cd /home/adminuser
runuser -u adminuser -- docker compose up -d

# Wait for containers
log info "Waiting for containers to be healthy..."
for i in 1 2 3 4 5 6 7 8 9 10 11 12; do
    RUNNING=$(runuser -u adminuser -- docker compose ps --filter "status=running" --services 2>/dev/null | wc -l)
    TOTAL=$(runuser -u adminuser -- docker compose ps --services 2>/dev/null | wc -l)
    if [ "$RUNNING" -eq "$TOTAL" ] && [ "$TOTAL" -gt 0 ]; then
        log info "All $TOTAL containers running"
        break
    fi
    log warning "Containers: $RUNNING/$TOTAL running (attempt $i/12)"
    sleep 10
done

# ============================================
# START TIMERS
# ============================================
systemctl start aitdr-collector.timer
systemctl start aitdr-suricata.timer

log info "=== Layer 2 Init complete ==="