#!/bin/bash

echo "Stopping AITDR Lab..."

# Remove temporary SSH access rules
az network nsg rule delete \
  --resource-group Bi_solution_rg \
  --nsg-name NSG-DMZ \
  --name Allow-SSH-Temp || true

az network nsg rule delete \
  --resource-group Bi_solution_rg \
  --nsg-name NSG-DMZ \
  --name Allow-SSH || true

# Deallocate VM to stop compute billing
az vm deallocate \
  --resource-group Bi_solution_rg \
  --name VM1-WebServer

az vm deallocate \
  --resource-group Bi_solution_rg \
  --name VM2-ML-Analysis

# Logout Azure session
az logout

echo "Lab stopped. Compute billing paused."