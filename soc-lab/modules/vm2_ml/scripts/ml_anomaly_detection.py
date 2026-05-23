#!/usr/bin/env python3
import pyodbc
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import DBSCAN
import joblib
import os

# ============================================
# CONFIG (Injected by Terraform)
# ============================================
SQL_SERVER   = "${sql_server_fqdn}"
SQL_DB       = "AttackLogsDB"
SQL_USER     = "sqladmin"
SQL_PASS     = "${sql_admin_password}"
MODEL_PATH   = "/var/lib/aitdr/models"

os.makedirs(MODEL_PATH, exist_ok=True)
print(f"[{datetime.now()}] Starting ML anomaly detection (Source: SQL)...")

# ============================================
# CONNECT TO SQL
# ============================================
try:
    conn = pyodbc.connect(
        f'DRIVER={{ODBC Driver 17 for SQL Server}};'
        f'SERVER={SQL_SERVER};DATABASE={SQL_DB};'
        f'UID={SQL_USER};PWD={SQL_PASS};'
        f'Encrypt=yes;TrustServerCertificate=no'
    )
    cursor = conn.cursor()

    # ============================================
    # FETCH DATA FROM SQL
    # ============================================
    print("Fetching SSH and Web data from SQL...")
    
    # Fetch SSH Data
    ssh_df = pd.read_sql("""
        SELECT
            CAST(attack_date AS DATETIME) as TimeGenerated,
            COUNT(*) as SSHAttempts,
            COUNT(DISTINCT attacker_ip) as UniqueIPs,
            COUNT(DISTINCT username_tried) as UniqueUsers
        FROM SSHAttacks
        GROUP BY attack_date
        ORDER BY attack_date
    """, conn)

    # Fetch Web Data
    sql_df = pd.read_sql("""
        SELECT
            CAST(attack_date AS DATETIME) as TimeGenerated,
            COUNT(*) as TotalAttacks,
            COUNT(DISTINCT attacker_ip) as UniqueIPs,
            SUM(CASE WHEN attack_type='SQLi' THEN 1 ELSE 0 END) as SQLi,
            SUM(CASE WHEN attack_type='XSS' THEN 1 ELSE 0 END) as XSS,
            SUM(CASE WHEN attack_type='Botnet' THEN 1 ELSE 0 END) as Botnet,
            SUM(CASE WHEN attack_type='BruteForce' THEN 1 ELSE 0 END) as BruteForce
        FROM WebAttacks
        GROUP BY attack_date
        ORDER BY attack_date
    """, conn)

    # Fetch Suricata (Network) Data
    suricata_df = pd.read_sql("""
        SELECT
            CAST(timestamp AS DATE) as TimeGenerated,
            COUNT(*) as TotalNetworkEvents,
            COUNT(DISTINCT src_ip) as UniqueSrcIPs,
            SUM(CASE WHEN alert_severity='1' THEN 1 ELSE 0 END) as CriticalAlerts,
            SUM(CASE WHEN event_type='alert' THEN 1 ELSE 0 END) as TotalAlerts
        FROM PacketLogs
        GROUP BY CAST(timestamp AS DATE)
        ORDER BY CAST(timestamp AS DATE)
    """, conn)

    print(f"Loaded: {len(ssh_df)} SSH rows, {len(sql_df)} Web rows, {len(suricata_df)} Network rows")

except Exception as e:
    print(f"SQL Read Error: {e}")
    suricata_df = pd.DataFrame()
    exit(1)

anomalies_found = []

# ============================================
# MODEL 1 - ISOLATION FOREST ON SSH
# ============================================
if not ssh_df.empty and len(ssh_df) > 5:
    try:
        features = ssh_df[['SSHAttempts','UniqueIPs','UniqueUsers']].fillna(0)
        scaler   = StandardScaler()
        scaled   = scaler.fit_transform(features)

        model = IsolationForest(contamination=0.1, random_state=42, n_estimators=100)
        ssh_df['anomaly_score'] = model.fit_predict(scaled)
        ssh_df['anomaly_raw']   = model.score_samples(scaled)
        ssh_df['is_anomaly']    = ssh_df['anomaly_score'] == -1

        joblib.dump(model, f"{MODEL_PATH}/iso_forest_ssh.pkl")

        for _, row in ssh_df[ssh_df['is_anomaly']].iterrows():
            anomalies_found.append({
                'time_window' : row.get('TimeGenerated', datetime.now()),
                'anomaly_type': 'SSH_Anomaly',
                'event_count' : int(row.get('SSHAttempts', 0)),
                'unique_ips'  : int(row.get('UniqueIPs', 0)),
                'anomaly_score': float(row.get('anomaly_raw', 0)),
                'confidence'  : 0.9,
                'model_used'  : 'IsolationForest',
                'description' : f"Unusual SSH: {int(row.get('SSHAttempts',0))} attempts from {int(row.get('UniqueIPs',0))} IPs",
                'raw_features': str({'SSHAttempts': int(row.get('SSHAttempts',0)), 'UniqueIPs': int(row.get('UniqueIPs',0))})
            })
    except Exception as e:
        print(f"SSH model error: {e}")

# ============================================
# MODEL 2 - ISOLATION FOREST ON WEB ATTACKS
# ============================================
if not sql_df.empty and len(sql_df) > 5:
    try:
        features = sql_df[['TotalAttacks','UniqueIPs','SQLi','XSS','Botnet','BruteForce']].fillna(0)
        scaler   = StandardScaler()
        scaled   = scaler.fit_transform(features)

        model = IsolationForest(contamination=0.1, random_state=42, n_estimators=100)
        sql_df['anomaly_score'] = model.fit_predict(scaled)
        sql_df['anomaly_raw']   = model.score_samples(scaled)
        sql_df['is_anomaly']    = sql_df['anomaly_score'] == -1

        for _, row in sql_df[sql_df['is_anomaly']].iterrows():
            anomalies_found.append({
                'time_window' : row.get('TimeGenerated', datetime.now()),
                'anomaly_type': 'Web_Anomaly',
                'event_count' : int(row.get('TotalAttacks', 0)),
                'unique_ips'  : int(row.get('UniqueIPs', 0)),
                'anomaly_score': float(row.get('anomaly_raw', 0)),
                'confidence'  : 0.85,
                'model_used'  : 'IsolationForest',
                'description' : f"Web Attack Spike: {int(row.get('TotalAttacks',0))} attacks from {int(row.get('UniqueIPs',0))} IPs",
                'raw_features': str({'TotalAttacks': int(row.get('TotalAttacks',0)), 'UniqueIPs': int(row.get('UniqueIPs',0))})
            })
    except Exception as e:
        print(f"Web model error: {e}")

# ============================================
# MODEL 3 - DBSCAN CLUSTERING
# ============================================
if not sql_df.empty and len(sql_df) > 10:
    try:
        features = sql_df[['TotalAttacks','UniqueIPs','SQLi','XSS']].fillna(0)
        scaler   = StandardScaler()
        scaled   = scaler.fit_transform(features)

        dbscan = DBSCAN(eps=0.5, min_samples=2)
        sql_df['cluster'] = dbscan.fit_predict(scaled)

        for _, row in sql_df[sql_df['cluster'] == -1].iterrows():
            anomalies_found.append({
                'time_window' : row.get('TimeGenerated', datetime.now()),
                'anomaly_type': 'Outlier_Campaign',
                'event_count' : int(row.get('TotalAttacks', 0)),
                'unique_ips'  : int(row.get('UniqueIPs', 0)),
                'anomaly_score': -1.0,
                'confidence'  : 0.75,
                'model_used'  : 'DBSCAN',
                'description' : f"Isolated campaign: {int(row.get('TotalAttacks',0))} attacks not matching known patterns",
                'raw_features': str({'TotalAttacks': int(row.get('TotalAttacks',0)), 'UniqueIPs': int(row.get('UniqueIPs',0))})
            })
    except Exception as e:
        print(f"DBSCAN error: {e}")

# ============================================
# MODEL 4 - ISOLATION FOREST ON SURICATA
# ============================================
if not suricata_df.empty and len(suricata_df) > 5:
    try:
        features = suricata_df[['TotalNetworkEvents','UniqueSrcIPs','CriticalAlerts','TotalAlerts']].fillna(0)
        scaler   = StandardScaler()
        scaled   = scaler.fit_transform(features)

        model = IsolationForest(contamination=0.1, random_state=42, n_estimators=100)
        suricata_df['anomaly_score'] = model.fit_predict(scaled)
        suricata_df['anomaly_raw']   = model.score_samples(scaled)
        suricata_df['is_anomaly']    = suricata_df['anomaly_score'] == -1

        joblib.dump(model, f"{MODEL_PATH}/iso_forest_suricata.pkl")

        for _, row in suricata_df[suricata_df['is_anomaly']].iterrows():
            anomalies_found.append({
                'time_window' : row.get('TimeGenerated', datetime.now()),
                'anomaly_type': 'Network_Anomaly',
                'event_count' : int(row.get('TotalNetworkEvents', 0)),
                'unique_ips'  : int(row.get('UniqueSrcIPs', 0)),
                'anomaly_score': float(row.get('anomaly_raw', 0)),
                'confidence'  : 0.88,
                'model_used'  : 'IsolationForest',
                'description' : f"Network Spike: {int(row.get('TotalNetworkEvents',0))} events, {int(row.get('CriticalAlerts',0))} critical from {int(row.get('UniqueSrcIPs',0))} IPs",
                'raw_features': str({'TotalEvents': int(row.get('TotalNetworkEvents',0)), 'Critical': int(row.get('CriticalAlerts',0))})
            })
    except Exception as e:
        print(f"Suricata model error: {e}")

# ============================================
# SAVE ANOMALIES TO SQL
# ============================================
for anomaly in anomalies_found:
    cursor.execute("""
        INSERT INTO MLAnomalies
            (time_window, anomaly_type, event_count, unique_ips,
             anomaly_score, confidence, model_used, description, raw_features)
        VALUES (?,?,?,?,?,?,?,?,?)
    """,
        anomaly['time_window'],
        anomaly['anomaly_type'],
        anomaly['event_count'],
        anomaly['unique_ips'],
        anomaly['anomaly_score'],
        anomaly['confidence'],
        anomaly['model_used'],
        anomaly['description'][:1000],
        anomaly['raw_features'][:500]
    )

conn.commit()
conn.close()
print(f"[{datetime.now()}] Done! Saved {len(anomalies_found)} anomalies ✅")
