#!/bin/bash
# ============================================
# collect_logs.sh - ORCHESTRATOR ONLY v3
# No analysis, no reports, no summaries
# Just: collect logs → trigger parsers → upload raw
# ============================================

set -e  # Exit on error

# Logging function
log() {
    echo "[$(date -Iseconds)] $1" | tee -a /var/log/collect_logs.log
}

log "========== COLLECTION START =========="

# ============================================
# 1. LOAD CONFIGURATION
# ============================================
if [ ! -f /home/adminuser/.env ]; then
    log "ERROR: .env file not found"
    exit 1
fi

# Source only needed variables
source /home/adminuser/.env

if [ -z "$STORAGE_ACCOUNT" ]; then
    log "ERROR: STORAGE_ACCOUNT not set"
    exit 1
fi

# ============================================
# 2. CREATE DIRECTORY STRUCTURE (atomic staging)
# ============================================
YEAR=$(date +%Y)
MONTH=$(date +%m)
WEEK=$(date +%V)
DAY=$(date +%Y-%m-%d)
TIMESTAMP=$(date +%s)

# Use staging directory to prevent partial uploads
STAGING_DIR="/home/adminuser/logs/staging/$TIMESTAMP"
FINAL_DIR="/home/adminuser/logs/$YEAR/$MONTH/week-$WEEK/$DAY"

mkdir -p "$STAGING_DIR"
log "Created staging directory: $STAGING_DIR"

# ============================================
# 3. COLLECT RAW LOGS (no parsing)
# ============================================

# Apache logs from DVWA - deterministic container name
DVWA_CONTAINER=""
# Try known container names in order
for container_name in "dvwa" "web-dvwa" "vulnerables-web-dvwa-1"; do
    if docker ps --format "{{.Names}}" | grep -qx "$container_name"; then
        DVWA_CONTAINER="$container_name"
        break
    fi
done

if [ -n "$DVWA_CONTAINER" ]; then
    log "Collecting Apache logs from container: $DVWA_CONTAINER"
    
    # Copy access log
    if docker cp "$DVWA_CONTAINER":/var/log/apache2/access.log "$STAGING_DIR/apache_access.log" 2>/dev/null; then
        log "Apache access log collected"
    else
        log "WARNING: Could not copy Apache access log"
    fi
    
    # Copy error log if exists
    if docker cp "$DVWA_CONTAINER":/var/log/apache2/error.log "$STAGING_DIR/apache_error.log" 2>/dev/null; then
        log "Apache error log collected"
    else
        log "WARNING: Could not copy Apache error log"
    fi
else
    log "WARNING: DVWA container not running (checked: dvwa, web-dvwa, vulnerables-web-dvwa-1)"
fi

# System logs
log "Collecting system logs"
cp /var/log/auth.log "$STAGING_DIR/auth.log" 2>/dev/null || log "WARNING: auth.log not found"
cp /var/log/syslog "$STAGING_DIR/syslog" 2>/dev/null || log "WARNING: syslog not found"

# Suricata logs (if they exist)
if [ -f /var/log/suricata/eve.json ]; then
    cp /var/log/suricata/eve.json "$STAGING_DIR/suricata_eve.json" 2>/dev/null || log "WARNING: Could not copy eve.json"
    log "Suricata eve.json collected"
fi

# Docker container state
log "Capturing Docker state"
docker ps > "$STAGING_DIR/docker_ps.txt"
docker ps -a > "$STAGING_DIR/docker_ps_all.txt"

# ============================================
# 4. UPLOAD RAW LOGS TO AZURE STORAGE
# ============================================
log "Uploading logs to Azure Storage"

# In production with MSI, skip auth check entirely - Azure CLI handles token refresh
# No need for az account show - just attempt upload
CONTAINER_NAME="attack-logs-raw"

# Create container if it doesn't exist (idempotent)
az storage container create \
    --account-name "$STORAGE_ACCOUNT" \
    --name "$CONTAINER_NAME" \
    --auth-mode login \
    >/dev/null 2>&1 || true

UPLOAD_FAILED=0

# Upload each log file from staging
for log_file in "$STAGING_DIR"/*; do
    if [ -f "$log_file" ]; then
        filename=$(basename "$log_file")
        blob_path="$YEAR/$MONTH/week-$WEEK/$DAY/$filename"
        
        az storage blob upload \
            --account-name "$STORAGE_ACCOUNT" \
            --container-name "$CONTAINER_NAME" \
            --name "$blob_path" \
            --file "$log_file" \
            --auth-mode login \
            --overwrite \
            >/dev/null 2>&1
        
        if [ $? -eq 0 ]; then
            log "Uploaded: $filename"
        else
            log "ERROR: Failed to upload $filename"
            UPLOAD_FAILED=1
        fi
    fi
done

# Only move to final directory after successful upload
if [ $UPLOAD_FAILED -eq 0 ]; then
    mkdir -p "$FINAL_DIR"
    mv "$STAGING_DIR"/* "$FINAL_DIR/" 2>/dev/null || true
    rmdir "$STAGING_DIR" 2>/dev/null || true
    log "Moved logs to final directory: $FINAL_DIR"
else
    log "WARNING: Upload failures detected, keeping logs in staging: $STAGING_DIR"
fi

# ============================================
# 5. TRIGGER PARSERS (ingestion pipeline)
# ============================================

log "Triggering log parsers"

# Initialize status variables
PY_STATUS=0
SURICATA_STATUS=0

# Parse Apache logs into SQL
if [ -f /home/adminuser/parse_logs.py ]; then
    python3 /home/adminuser/parse_logs.py >> /var/log/collect_logs.log 2>&1
    PY_STATUS=$?
    log "parse_logs.py exit code: $PY_STATUS"
else
    log "ERROR: parse_logs.py not found"
    PY_STATUS=1
fi

# Parse Suricata network telemetry into SQL
if [ -f /home/adminuser/parse_suricata.py ]; then
    python3 /home/adminuser/parse_suricata.py >> /var/log/collect_logs.log 2>&1
    SURICATA_STATUS=$?
    log "parse_suricata.py exit code: $SURICATA_STATUS"
else
    log "ERROR: parse_suricata.py not found"
    SURICATA_STATUS=1
fi

# ============================================
# 6. CLEANUP (safe - only after successful processing)
# ============================================
log "Cleaning logs older than 7 days"

# Use find with -exec to handle failures gracefully
# Only delete from final directory, never from staging
find /home/adminuser/logs/2* -type f -mtime +7 -exec rm -f {} \; 2>/dev/null || true
find /home/adminuser/logs -type d -empty -mtime +1 -delete 2>/dev/null || true

# Clean old staging directories (older than 24 hours)
find /home/adminuser/logs/staging -type d -mtime +1 -exec rm -rf {} \; 2>/dev/null || true

log "========== COLLECTION COMPLETE =========="

# Exit with composite status
# 0 = success, 1 = any parser failed
if [ $PY_STATUS -ne 0 ] || [ $SURICATA_STATUS -ne 0 ]; then
    log "WARNING: One or more parsers failed (PY=$PY_STATUS, SURICATA=$SURICATA_STATUS)"
    exit 1
else
    log "All parsers completed successfully"
    exit 0
fi