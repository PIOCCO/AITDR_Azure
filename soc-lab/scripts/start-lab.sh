#!/bin/bash
# ============================================
# start-lab.sh - Dynamic Lab Orchestrator
# ============================================
set -e

RESOURCE_GROUP="Bi_solution_rg"
VM_WEB="VM1-WebServer"
VM_ML="VM2-ML-Analysis"
NSG_NAME="NSG-DMZ"

echo "🚀 Starting AITDR Lab Environment..."

# 1. Start VMs in parallel
echo "Starting Virtual Machines..."
az vm start --resource-group "$RESOURCE_GROUP" --name "$VM_WEB" --no-wait
az vm start --resource-group "$RESOURCE_GROUP" --name "$VM_ML" --no-wait

# 2. Wait for WebServer to be ready
echo "Waiting for $VM_WEB to reach 'Running' state..."
az vm wait --resource-group "$RESOURCE_GROUP" --name "$VM_WEB" --updated

# 3. Get dynamic Public IP
echo "Querying Public IP for $VM_WEB..."
VM_IP=$(az vm show -d -g "$RESOURCE_GROUP" -n "$VM_WEB" --query publicIps -o tsv)

if [ -z "$VM_IP" ]; then
    echo "❌ Error: Could not retrieve Public IP for $VM_WEB"
    exit 1
fi

echo "✅ $VM_WEB is up at: $VM_IP"

# 4. Handle NSG Rule for SSH
MY_IP=$(curl -s https://ifconfig.me)
echo "Detecting your local public IP: $MY_IP"

echo "Updating NSG rule 'Allow-SSH-Temp' to allow access from $MY_IP..."
az network nsg rule create \
    --resource-group "$RESOURCE_GROUP" \
    --nsg-name "$NSG_NAME" \
    --name "Allow-SSH-Temp" \
    --priority 150 \
    --direction Inbound \
    --access Allow \
    --protocol Tcp \
    --destination-port-range 22 \
    --source-address-prefixes "$MY_IP/32" \
    --description "Temporary SSH access for AITDR Lab" \
    >/dev/null

# 5. Clear old SSH fingerprint to avoid conflict
echo "Cleaning old SSH fingerprints for $VM_IP..."
ssh-keygen -R "$VM_IP" 2>/dev/null || true

echo "------------------------------------------------"
echo "🎉 Lab started successfully!"
echo "------------------------------------------------"
echo "💻 Web Server:   http://$VM_IP/dvwa"
echo "🔐 SSH Command:  ssh -o StrictHostKeyChecking=no adminuser@$VM_IP"
echo "------------------------------------------------"