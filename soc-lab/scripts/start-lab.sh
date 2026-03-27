#!/bin/bash
echo "Starting AITDR Lab..."

# Start VM
az vm start \
  --resource-group Bi_solution_rg \
  --name VM1-WebServer

# Wait for VM to boot
echo "Waiting for VM to start..."
sleep 60

# Get current IP
MY_IP=$(curl -s ifconfig.me)
echo "Your IP: $MY_IP"

# Add SSH rule
az network nsg rule create \
  --resource-group Bi_solution_rg \
  --nsg-name NSG-DMZ \
  --name Allow-SSH-Temp \
  --priority 150 \
  --direction Inbound \
  --access Allow \
  --protocol Tcp \
  --destination-port-range 22 \
  --source-address-prefixes "$MY_IP/32"

# Clear old SSH fingerprint
ssh-keygen -R 20.199.184.20

echo "Lab started! ✅"
echo "SSH: ssh -i ~/.ssh/id_ed25519 adminuser@20.199.184.20"