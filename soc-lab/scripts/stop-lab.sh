#!/bin/bash
# ============================================
# stop-lab.sh - Dynamic Lab Shutdown
# ============================================

RESOURCE_GROUP="Bi_solution_rg"
VM_WEB="VM1-WebServer"
VM_ML="VM2-ML-Analysis"
NSG_NAME="NSG-DMZ"

echo "🛑 Stopping AITDR Lab Environment..."

# 1. Remove temporary NSG rules
echo "Cleaning up temporary NSG rules..."
az network nsg rule delete \
    --resource-group "$RESOURCE_GROUP" \
    --nsg-name "$NSG_NAME" \
    --name "Allow-SSH-Temp" --no-wait 2>/dev/null || true

az network nsg rule delete \
    --resource-group "$RESOURCE_GROUP" \
    --nsg-name "$NSG_NAME" \
    --name "Allow-SSH" --no-wait 2>/dev/null || true

# 2. Deallocate VMs in parallel to save costs
echo "Deallocating Virtual Machines (Parallel)..."
az vm deallocate --resource-group "$RESOURCE_GROUP" --name "$VM_WEB" --no-wait
az vm deallocate --resource-group "$RESOURCE_GROUP" --name "$VM_ML" --no-wait

# 3. Final cleanup and Security Logout
echo "Finalizing security cleanup..."
# Delete any local Azure session tokens for maximum security
az logout 2>/dev/null || true
echo "Azure CLI session logged out."

echo "Lab shutdown initiated in the background."
echo "------------------------------------------------"
echo "✅ VM Deallocation: [PENDING/IN-PROGRESS]"
echo "✅ NSG Cleanup:      [INITIATED]"
echo "------------------------------------------------"
echo "💡 Tip: Compute billing pauses once deallocation completes."
echo "     You can close this terminal now."
echo "------------------------------------------------"