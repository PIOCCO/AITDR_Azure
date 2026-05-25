# AITDR — Azure Intelligent Threat Detection & Response

<div align="center">

![Azure](https://img.shields.io/badge/Azure-Cloud-0078D4?style=for-the-badge&logo=microsoftazure)
![Terraform](https://img.shields.io/badge/Terraform-IaC-7B42BC?style=for-the-badge&logo=terraform)
![Python](https://img.shields.io/badge/Python-3.10-3776AB?style=for-the-badge&logo=python)
![Sentinel](https://img.shields.io/badge/Microsoft-Sentinel-0078D4?style=for-the-badge&logo=microsoft)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Budget](https://img.shields.io/badge/Budget-100%20USD-orange?style=for-the-badge)

**A full cloud SOC platform on Azure — automated threat detection, ML anomaly detection, and SOAR incident response.**

[Overview](#-overview) • [Architecture](#-architecture) • [Prerequisites](#-prerequisites) • [Deployment](#-deployment) • [Start the Lab](#-start-the-lab) • [Results](#-results) • [Cost](#-cost)

</div>

---

## 📌 Overview

AITDR is a fully automated Security Operations Center (SOC) built on Microsoft Azure. It captures real cyberattacks via a DVWA honeypot, correlates events through Microsoft Sentinel, detects behavioural anomalies with unsupervised Machine Learning, and automatically blocks malicious IPs via Azure Logic Apps (SOAR) — all for under **$100**.

### What it does

| Layer | Component | Role |
|---|---|---|
| Capture | DVWA + Suricata | Attracts real attackers, analyses packets in real time |
| Data | Python pipeline + Azure SQL | Classifies and stores attack logs every 5 minutes |
| Detection | Microsoft Sentinel + KQL | Correlates events, generates incidents |
| Intelligence | Isolation Forest + DBSCAN | Detects anomalies without signatures |
| Response | Azure Logic Apps (SOAR) | Blocks IPs in NSG in under 30 seconds |
| Visualisation | Power BI + Azure SQL | Real-time dashboards, always available |

### Real results (5-day test)

```
First attack after deployment   →  18 minutes
SSH brute force attempts        →  1,247
Malicious HTTP requests         →  8,934
SQL injection attempts          →  312
Sentinel incidents generated    →  18
NSG rules created automatically →  18
ML anomalies detected           →  7
Average detection-to-block time →  4 min 51 sec
Total budget consumed           →  $87.40 / $100
```

---

## 🏗 Architecture

```
                        ┌─────────────────────────────────────────────┐
                        │              INTERNET                        │
                        └────────────────────┬────────────────────────┘
                                             │ Port 80/443 (DVWA)
                        ┌────────────────────▼────────────────────────┐
                        │         VNet1 — DMZ  (10.10.1.0/24)         │
                        │  ┌─────────────────────────────────────┐    │
                        │  │  VM1-WebServer  (20.199.184.20)      │    │
                        │  │  ├── Docker: DVWA + MySQL            │    │
                        │  │  ├── Suricata IDS/IPS (EVE JSON)     │    │
                        │  │  ├── Fail2ban                        │    │
                        │  │  ├── collect_logs.sh (timer 5min)    │    │
                        │  │  └── parse_logs.py / suricata.py     │    │
                        │  └─────────────────────────────────────┘    │
                        └──────────┬──────────────────┬───────────────┘
                                   │ SQL:1433          │ HTTPS:443
                   ┌───────────────▼──────┐   ┌───────▼───────────────┐
                   │  VNet2 — Data         │   │  Azure Blob Storage    │
                   │  (10.10.2.0/24)       │   │  attack-logs/          │
                   │  ┌─────────────────┐  │   └───────────────────────┘
                   │  │ Azure SQL DB    │  │
                   │  │ AttackLogsDB    │  │
                   │  │ ├── WebAttacks  │  │
                   │  │ ├── SSHAttacks  │  │
                   │  │ ├── PacketLogs  │  │
                   │  │ ├── DailySummary│  │
                   │  │ └── MLAnomalies │  │
                   │  └────────┬────────┘  │
                   └───────────┼───────────┘
                               │ Read (ML)
                   ┌───────────▼──────────────────────────────────────┐
                   │          VNet3 — SIEM/SOAR  (10.10.3.0/24)       │
                   │  ┌──────────────────┐  ┌──────────────────────┐  │
                   │  │ Microsoft Sentinel│  │  VM2-ML (10.10.2.40) │  │
                   │  │ ├── KQL Rules     │  │  ├── Isolation Forest │  │
                   │  │ ├── Incidents     │  │  ├── DBSCAN           │  │
                   │  │ └── Auto Rules    │  │  └── joblib models    │  │
                   │  └────────┬─────────┘  └──────────────────────┘  │
                   │           │ Trigger                                │
                   │  ┌────────▼─────────────────────────────────┐     │
                   │  │  Azure Logic Apps — SOAR                  │     │
                   │  │  ├── SOAR-Ban-Attacker (NSG block)        │     │
                   │  │  └── SOAR-Email-Alert (notifications)     │     │
                   │  └──────────────────────────────────────────┘     │
                   └──────────────────────────────────────────────────┘
                                           │
                   ┌───────────────────────▼──────────────────────────┐
                   │          Hub VNet  (10.10.0.0/24)                  │
                   │          VPN Gateway — Admin access                 │
                   └──────────────────────────────────────────────────┘

                   Power BI ──────────────────────────► Azure SQL (Direct Query)
                   (Always available, VM-independent)
```

### SOAR Response Logic

```
Sentinel Incident
       │
       ▼
Logic App triggered
       │
       ▼
Normalize incidentType (toLower)
       │
       ├── rce / cmdi   → Block IP in NSG + Deallocate VM  (<30s)
       ├── sqli         → Block IP in NSG + Email alert    (<30s)
       ├── bruteforce   → Block IP in NSG + Email alert    (<30s)
       ├── ssh          → Block IP in NSG                  (<30s)
       ├── lfi          → Block IP in NSG                  (<30s)
       ├── xss / csrf   → Log only                        (immediate)
       └── default      → Block IP in NSG                  (<30s)

NSG Rule name: AutoBan-{IP-with-dashes}
NSG Priority:  200 + last octet of attacker IP
```

---

## 📋 Prerequisites

### Accounts and tools

| Tool | Version | Install |
|---|---|---|
| Azure CLI | 2.x+ | [docs.microsoft.com](https://docs.microsoft.com/cli/azure/install-azure-cli) |
| Terraform | 1.7+ | [terraform.io](https://developer.hashicorp.com/terraform/install) |
| Git | any | [git-scm.com](https://git-scm.com) |
| Python | 3.10+ | [python.org](https://www.python.org) |
| Power BI Desktop | latest | [powerbi.microsoft.com](https://powerbi.microsoft.com) |

### Azure requirements

- An active Azure subscription
- Owner or Contributor role on the subscription
- Sufficient quota for 2× `Standard_B2s` VMs in your chosen region

### Local files you need to create

```bash
# SSH key pair for VM access
ssh-keygen -t rsa -b 4096 -f ~/.ssh/aitdr_rsa

# Your public IP (to allow SSH access)
curl -s ifconfig.me
```

---

## 📁 Repository Structure

```
aitdr/
├── main.tf                        # Root Terraform orchestration
├── variables.tf                   # Input variable declarations
├── outputs.tf                     # Output values after deploy
├── terraform.tfvars.example       # Template — copy and fill in
│
├── modules/
│   ├── key_vault/
│   │   ├── main.tf                # Azure Key Vault + RBAC
│   │   └── outputs.tf
│   │
│   ├── vm1_webserver/
│   │   ├── main.tf                # Honeypot VM + Identity + auto-shutdown
│   │   ├── outputs.tf
│   │   └── scripts/
│   │       ├── custom_data.sh.tpl # cloud-init bootstrap (Layer 1)
│   │       ├── aitdr-init.sh      # systemd secrets fetcher (Layer 2)
│   │       ├── collect_logs.sh    # Log collector (Layer 3 - every 5min)
│   │       ├── parse_logs.py      # Attack classifier → SQL
│   │       └── parse_suricata.py  # EVE JSON parser → SQL
│   │
│   ├── vm2_ml/
│   │   ├── main.tf                # ML VM (no public IP)
│   │   └── scripts/
│   │       └── ml_anomaly_detection.py  # Isolation Forest + DBSCAN
│   │
│   ├── sql_database/
│   │   ├── main.tf                # Azure SQL Server + DB + firewall
│   │   └── create_tables.sql      # DDL for 5 tables
│   │
│   ├── sentinel/
│   │   ├── main.tf                # Workspace + AMA + DCR + alert rules
│   │   └── alert_rules.kql        # KQL detection rules
│   │
│   ├── soar/
│   │   ├── main.tf                # RBAC + Sentinel Automation Rules
│   │   ├── logic_app.json         # ARM: Ban Attacker workflow
│   │   └── email_app.json         # ARM: Email Alert workflow
│   │
│   ├── nsg/
│   │   └── main.tf                # NSG rules for DMZ, Data, SIEM
│   │
│   ├── vnet1/                     # DMZ subnet 10.10.1.0/24
│   ├── vnet2/                     # Data subnet 10.10.2.0/24
│   ├── vnet3/                     # SIEM subnet 10.10.3.0/24
│   └── hub_vnet/                  # Hub + VPN Gateway
│
├── scripts/
│   ├── start-lab.sh               # Start the lab each session
│   ├── stop-lab.sh                # Deallocate VMs to save cost
│   └── create_tables.sql          # Run manually in Azure portal
│
└── powerbi/
    └── AITDR_Dashboard.pbix       # Power BI report file
```

---

## 🚀 Deployment

### Step 1 — Clone the repository

```bash
git clone https://github.com/your-username/aitdr.git
cd aitdr
```

### Step 2 — Configure your variables

```bash
cp terraform.tfvars.example terraform.tfvars
```

Open `terraform.tfvars` and fill in your values:

```hcl
# terraform.tfvars  — DO NOT COMMIT THIS FILE
resource_group_name = "Bi_solution_rg"
location            = "westeurope"
subscription_id     = "your-subscription-id"
tenant_id           = "your-tenant-id"
admin_object_id     = "your-aad-object-id"   # az ad signed-in-user show --query id -o tsv

ssh_public_key      = "ssh-rsa AAAA...your-public-key"
kali_ip             = "your.current.public.ip"   # curl ifconfig.me

sql_admin_password  = "YourStr0ngP@ssword!"
alert_email         = "your@email.com"
```

> ⚠️ `terraform.tfvars` is already in `.gitignore`. Never commit it.

### Step 3 — Authenticate to Azure

```bash
az login
az account set --subscription "your-subscription-id"
```

### Step 4 — Deploy in the correct order

```bash
# Initialize Terraform
terraform init

# Preview the deployment plan
terraform plan

# Deploy SQL first (FQDN needed for Key Vault secrets)
terraform apply -target module.sql_database -auto-approve

# Deploy Key Vault with SQL credentials as secrets
terraform apply -target module.key_vault -auto-approve

# Deploy Sentinel workspace
terraform apply -target module.sentinel -auto-approve

# Deploy VM1 (receives Key Vault URI only — no secrets in code)
terraform apply -target module.vm1_webserver -auto-approve

# Deploy everything else
terraform apply -auto-approve
```

> ⏱ Full deployment takes approximately **15–25 minutes**.

### Step 5 — Create the SQL tables

Navigate to **Azure Portal → AttackLogsDB → Query Editor** and run:

```sql
-- Copy content from scripts/create_tables.sql
-- or run it via Azure CLI:
az sql db execute \
  --resource-group Bi_solution_rg \
  --server your-sql-server \
  --database AttackLogsDB \
  --file scripts/create_tables.sql
```

### Step 6 — Connect Logic Apps to Sentinel

In the Azure Portal:
1. Go to **Microsoft Sentinel → Automation → Playbooks**
2. Click **Manage playbook permissions**
3. Select your resource group
4. Save

This allows Sentinel Automation Rules to trigger the Logic Apps.

---

## ▶️ Start the Lab

At the beginning of each work session, run the startup script:

```bash
chmod +x scripts/start-lab.sh
./scripts/start-lab.sh
```

The script will:
- Start VM1 (honeypot) and optionally VM2 (ML)
- Detect your current public IP automatically
- Update the NSG SSH rule to allow only your IP
- Print the SSH connection command

```bash
# Manual equivalent
MY_IP=$(curl -s ifconfig.me)

# Start VMs
az vm start --resource-group Bi_solution_rg --name VM1-WebServer
az vm start --resource-group Bi_solution_rg --name VM2-ML   # optional

# Update SSH rule
az network nsg rule update \
  --resource-group Bi_solution_rg \
  --nsg-name NSG-DMZ \
  --name Allow-SSH-Admin \
  --source-address-prefixes "$MY_IP/32"

# Connect to VM1
ssh -i ~/.ssh/aitdr_rsa adminuser@20.199.184.20
```

### Check the system status on VM1

```bash
# Check all services
sudo systemctl status aitdr-init.service
sudo systemctl status aitdr-collector.timer
sudo systemctl status aitdr-suricata.timer
sudo systemctl status docker

# Check containers
docker ps

# View last collection run
sudo journalctl -u aitdr-collector.service -n 50

# View init logs
sudo journalctl -u aitdr-init -n 100 --no-pager

# Manually trigger a collection immediately
sudo systemctl start aitdr-collector.service

# Check Suricata alerts
sudo tail -f /var/log/suricata/eve.json | jq '.event_type'

# View live Apache logs from DVWA container
docker logs dvwa-1 -f
```

### Check attack data in SQL

Connect to Azure SQL via the portal Query Editor:

```sql
-- Latest web attacks
SELECT TOP 20 attacker_ip, attack_type, url_path, attack_time
FROM WebAttacks
ORDER BY attack_time DESC;

-- Top attacking IPs
SELECT attacker_ip, COUNT(*) as attempts, attack_type
FROM WebAttacks
GROUP BY attacker_ip, attack_type
ORDER BY attempts DESC;

-- SSH brute force summary
SELECT attacker_ip, COUNT(*) as attempts,
       COUNT(DISTINCT username_tried) as usernames_tried
FROM SSHAttacks
GROUP BY attacker_ip
ORDER BY attempts DESC;

-- Daily summary
SELECT * FROM DailySummary ORDER BY summary_date DESC;

-- ML anomalies
SELECT * FROM MLAnomalies ORDER BY detected_at DESC;
```

---

## ⏹ Stop the Lab (Save Cost)

```bash
chmod +x scripts/stop-lab.sh
./scripts/stop-lab.sh
```

Or manually:

```bash
# Deallocate (stops billing for compute — disk still billed)
az vm deallocate --resource-group Bi_solution_rg --name VM1-WebServer
az vm deallocate --resource-group Bi_solution_rg --name VM2-ML

# Verify deallocated
az vm show --resource-group Bi_solution_rg --name VM1-WebServer \
  --query "powerState" -o tsv
# Expected: VM deallocated
```

> 💡 VMs are also auto-shutdown daily at **23:00 UTC** via the Terraform config.

---

## 🔍 Monitoring and Alerts

### Sentinel KQL Queries

Run these in **Microsoft Sentinel → Logs**:

```kql
-- SSH Brute Force Detection
Syslog
| where Facility == "auth"
| where SyslogMessage contains "Invalid user"
| extend AttackerIP = extract(@"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", 1, SyslogMessage)
| summarize Count = count() by AttackerIP, bin(TimeGenerated, 5m)
| where Count > 10
| order by Count desc

-- Mozi Botnet Detection
Syslog
| where SyslogMessage contains "setup.cgi" or SyslogMessage contains "Mozi"
| extend AttackerIP = extract(@"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", 1, SyslogMessage)
| project TimeGenerated, AttackerIP, SyslogMessage

-- All incidents last 24h
SecurityIncident
| where TimeGenerated > ago(24h)
| project TimeGenerated, Title, Severity, Status
| order by TimeGenerated desc
```

### Check NSG auto-ban rules

```bash
# List all auto-ban rules created by SOAR
az network nsg rule list \
  --resource-group Bi_solution_rg \
  --nsg-name NSG-DMZ \
  --query "[?contains(name, 'AutoBan')]" \
  --output table

# Remove a specific ban (if you need to unban)
az network nsg rule delete \
  --resource-group Bi_solution_rg \
  --nsg-name NSG-DMZ \
  --name "AutoBan-143-198-24-202"
```

### Run ML detection manually on VM2

```bash
ssh -i ~/.ssh/aitdr_rsa adminuser@20.199.184.20   # jump through VM1
ssh 10.10.2.40                                      # then to VM2

# Run anomaly detection
python3 /home/adminuser/ml_anomaly_detection.py

# Check saved models
ls /home/adminuser/models/
# ssh_if.pkl  ssh_scaler.pkl  web_if.pkl  web_scaler.pkl
```

---

## 💰 Cost

The entire project was built and tested for under **$100**.

| Component | Tier | Cost |
|---|---|---|
| VM1 WebServer (Standard_B2s) | 720h active | $29.95 |
| VM2 ML (Standard_B2s) | 480h active | $19.97 |
| Microsoft Sentinel | PAYG 3.2 GB ingested | $11.04 |
| Azure SQL Database | Basic tier | $9.80 |
| Public IP (static) | Standard SKU | $7.30 |
| Bandwidth + Storage | LRS Hot | $3.28 |
| Logic Apps | PAYG executions | $0.30 |
| Key Vault, AMA, NSG | Free / included | $0.00 |
| **Total** | | **$87.40** |

### Cost reduction tips

```bash
# Use B1s instead of B2s for VM1 if only running DVWA (~50% cheaper)
# Activate Sentinel 31-day free trial for new workspaces
# Use Spot instances for VM2 (ML batch — 60-90% cheaper)
# Keep DCR filter to Warning+ only (saves ~70% on Sentinel ingestion)
```

---

## 🛡 Security Design

- **No secrets in code** — all credentials live in Azure Key Vault, fetched at runtime via Managed Identity and IMDS
- **Zero static passwords** — SSH key-only authentication (RSA 4096)
- **Least privilege RBAC** — each component has only the permissions it needs, scoped to the exact target resource
- **Network segmentation** — Deny-All NSG rule (priority 4096) on every zone; all traffic is explicitly whitelisted
- **IMDS blocked from containers** — `iptables -I DOCKER-USER -d 169.254.169.254 -j DROP` prevents token theft from DVWA
- **Purge protection** — Key Vault cannot be permanently deleted even by an admin

| Component | Role | Scope |
|---|---|---|
| VM1 Managed Identity | Key Vault Secrets User | Key Vault only |
| VM1 Managed Identity | Storage Blob Contributor | Storage Account only |
| Logic App SOAR | Network Contributor | NSG-DMZ only |
| Logic App SOAR | Virtual Machine Contributor | VM1-WebServer only |
| VM2 Managed Identity | SQL DB Contributor | AttackLogsDB only |

---

## ❗ Troubleshooting

### VM1 is not collecting logs

```bash
# Check aitdr-init completed successfully
sudo systemctl status aitdr-init.service
# Should show: active (exited)

# If it failed, check why
sudo journalctl -u aitdr-init --no-pager -n 50

# Common cause: RBAC not propagated yet (wait 5 min and retry)
sudo rm /home/adminuser/.env
sudo systemctl restart aitdr-init.service
```

### SSH connection refused

```bash
# Your IP probably changed — update the NSG rule
MY_IP=$(curl -s ifconfig.me)
az network nsg rule update \
  --resource-group Bi_solution_rg \
  --nsg-name NSG-DMZ \
  --name Allow-SSH-Admin \
  --source-address-prefixes "$MY_IP/32"
```

### Banned by Fail2ban

```bash
# Use Azure Run Command to unban yourself without SSH
az vm run-command invoke \
  --resource-group Bi_solution_rg \
  --name VM1-WebServer \
  --command-id RunShellScript \
  --scripts "fail2ban-client set sshd unbanip YOUR_IP"
```

### DVWA container not running

```bash
ssh -i ~/.ssh/aitdr_rsa adminuser@20.199.184.20
cd /home/adminuser
docker compose ps
docker compose up -d
docker compose logs dvwa
```

### NSG priority collision (two IPs with same last octet)

```bash
# The Logic App uses 200 + last_octet as priority
# If two IPs share the last octet, the PUT is idempotent — it updates the rule
# Check existing rules
az network nsg rule list \
  --resource-group Bi_solution_rg \
  --nsg-name NSG-DMZ \
  --query "[?contains(name,'AutoBan')]" -o table
```

### Terraform state drift (Logic App)

```bash
# Logic Apps are ARM-owned — do not import them into Terraform state
# If drift is detected, run:
terraform plan
# Only RBAC and Automation Rules should show changes
# If Logic App itself shows as changed, check ARM deployment status in portal
```

---

## 🔄 Destroy the Lab

```bash
# WARNING: This deletes everything
terraform destroy -auto-approve
```

> 💡 The Key Vault enters a **soft-delete** period of 7 days. To permanently purge it:
```bash
az keyvault purge --name aitdr-kv-xxxxxx --location westeurope
```

---

## 📊 Power BI Setup

1. Open `powerbi/AITDR_Dashboard.pbix` in Power BI Desktop
2. Click **Transform Data → Data Source Settings**
3. Update the server to: `aitdr-sql-server-xxxxx.database.windows.net`
4. Enter credentials: username `sqladmin`, your SQL password
5. Add your IP to the SQL Server firewall in the Azure Portal
6. Click **Refresh**

The dashboard works even when all VMs are off — it connects directly to Azure SQL.

---

## 🗺 Roadmap

- [ ] Connect Logic Apps to Sentinel Automation Rules via portal
- [ ] Add IP geolocation enrichment via ipinfo.io API
- [ ] Calibrate ML contamination parameter after 30 days of data
- [ ] Configure Office 365 connector in SOAR-Email-Alert
- [ ] Integrate AbuseIPDB threat intelligence feed
- [ ] Convert Sigma community rules to KQL via sigma-cli
- [ ] Add multi-region honeypot deployment
- [ ] Migrate ML workloads to AKS with Spot node pools
- [ ] Add LLM-generated incident summary reports

---

## 👥 Authors

| Name | Role |
|---|---|
| CHBANE Labib | Cloud Infrastructure, Terraform, SOAR |
| GAMMAL Oussama | Security Pipeline, ML, Sentinel KQL |

**École Marocaine des Sciences de l'Ingénieur (EMSI)**  
Filière : Cybersécurité & Infrastructure Réseaux — 4ème année

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

<div align="center">

**⭐ Star this repo if it helped you build a real SOC lab on a student budget.**

</div>
