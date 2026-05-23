import pyodbc
import pandas as pd
from neo4j import GraphDatabase
from datetime import datetime
import os
import getpass

# ============================================
# CONFIGURATION
# ============================================
# Azure SQL Configuration
SQL_SERVER   = os.getenv("SQL_SERVER", "aitdr-sql-server-wxqe4f.database.windows.net")
SQL_DB       = os.getenv("SQL_DB", "AttackLogsDB")
SQL_USER     = os.getenv("SQL_USER", "sqladmin")
SQL_PASS     = os.getenv("SQL_PASS") or getpass.getpass("Enter Azure SQL Password: ")

# Local Neo4j Configuration
NEO4J_URI    = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER   = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASS   = os.getenv("NEO4J_PASS") or getpass.getpass("Enter Local Neo4j Password: ")

print(f"[{datetime.now()}] Starting Local Neo4j Ingestion...")

# ============================================
# CONNECT TO SQL
# ============================================
try:
    print("Connecting to Azure SQL...")
    conn_str = (
        f'DRIVER={{ODBC Driver 17 for SQL Server}};'
        f'SERVER={SQL_SERVER};DATABASE={SQL_DB};'
        f'UID={SQL_USER};PWD={SQL_PASS};'
        f'Encrypt=yes;TrustServerCertificate=no'
    )
    sql_conn = pyodbc.connect(conn_str)
    
    # Fetch Web Attacks
    print("Fetching Web Attacks...")
    web_df = pd.read_sql("SELECT attacker_ip, attack_type, url_path, attack_date FROM WebAttacks", sql_conn)
    
    # Fetch SSH Attacks
    print("Fetching SSH Attacks...")
    ssh_df = pd.read_sql("SELECT attacker_ip, username_tried, attack_date FROM SSHAttacks", sql_conn)
    
    # Fetch Packet Logs (For Beaconing and Lateral Movement)
    print("Fetching Packet Logs...")
    packet_df = pd.read_sql("SELECT src_ip, dest_ip, src_port, dest_port, protocol, event_type, alert_severity FROM PacketLogs", sql_conn)
    
    # Fetch ML Anomalies (For Campaigns)
    print("Fetching ML Anomalies...")
    anomalies_df = pd.read_sql("SELECT anomaly_type, detected_at, event_count, unique_ips, description FROM MLAnomalies", sql_conn)

except Exception as e:
    print(f"Failed to connect or read from Azure SQL: {e}")
    exit(1)
finally:
    if 'sql_conn' in locals():
        sql_conn.close()

# ============================================
# CONNECT TO NEO4J & INGEST
# ============================================
try:
    print(f"Connecting to Local Neo4j at {NEO4J_URI}...")
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))
    
    def clear_database(tx):
        tx.run("MATCH (n) DETACH DELETE n")

    def ingest_infrastructure(tx, ip_list):
        for ip in ip_list:
            is_internal = ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.")
            tx.run(
                "MERGE (n:IPAddress {ip: $ip}) "
                "SET n.type = $type",
                ip=ip, type="Internal" if is_internal else "External"
            )

    def ingest_web_attacks(tx, df):
        for _, row in df.iterrows():
            tx.run(
                "MERGE (attacker:IPAddress {ip: $ip}) "
                "MERGE (target:IPAddress {ip: 'Web_Server_Internal'}) " # Abstraction for Target
                "MERGE (attacker)-[r:WEB_ATTACK {type: $attack_type, path: $path, date: $date}]->(target)",
                ip=row['attacker_ip'], 
                attack_type=row['attack_type'], 
                path=row['url_path'] if row['url_path'] else "N/A",
                date=str(row['attack_date'])
            )

    def ingest_ssh_attacks(tx, df):
        for _, row in df.iterrows():
            tx.run(
                "MERGE (attacker:IPAddress {ip: $ip}) "
                "MERGE (target:IPAddress {ip: 'SSH_Server_Internal'}) "
                "MERGE (attacker)-[r:SSH_BRUTE_FORCE {user_tried: $user, date: $date}]->(target)",
                ip=row['attacker_ip'], 
                user=row['username_tried'],
                date=str(row['attack_date'])
            )

    def ingest_packet_logs(tx, df):
        for _, row in df.iterrows():
            src_ip = row['src_ip']
            dest_ip = row['dest_ip']
            
            # Simple check for lateral movement
            src_internal = src_ip.startswith("10.") or src_ip.startswith("192.168.")
            dest_internal = dest_ip.startswith("10.") or dest_ip.startswith("192.168.")
            
            rel_type = "LATERAL_MOVEMENT" if (src_internal and dest_internal) else "COMMUNICATED_WITH"
            
            tx.run(
                f"MERGE (src:IPAddress {{ip: $src_ip}}) "
                f"MERGE (dest:IPAddress {{ip: $dest_ip}}) "
                f"MERGE (src)-[r:{rel_type} {{port: $dest_port, protocol: $protocol, severity: $severity}}]->(dest)",
                src_ip=src_ip,
                dest_ip=dest_ip,
                dest_port=row['dest_port'],
                protocol=row['protocol'] if row['protocol'] else "N/A",
                severity=row['alert_severity'] if row['alert_severity'] else "0"
            )

    def ingest_campaigns(tx, df):
        for _, row in df.iterrows():
            # Create a campaign node
            tx.run(
                "MERGE (c:Campaign {type: $anomaly_type, date: $date}) "
                "SET c.description = $desc, c.event_count = $count, c.unique_ips = $ips",
                anomaly_type=row['anomaly_type'],
                date=str(row['detected_at']),
                desc=row['description'],
                count=row['event_count'],
                ips=row['unique_ips']
            )
            # In a real scenario, you'd join this with specific IPs that participated.
            # Here we just create the campaign nodes so they can be visualized.

    with driver.session() as session:
        print("Clearing existing Neo4j database...")
        session.execute_write(clear_database)
        
        # Gather all unique IPs for infrastructure mapping
        all_ips = set(web_df['attacker_ip'].dropna()).union(
                  set(ssh_df['attacker_ip'].dropna())).union(
                  set(packet_df['src_ip'].dropna())).union(
                  set(packet_df['dest_ip'].dropna()))
                  
        print(f"Ingesting {len(all_ips)} unique IPs for Infrastructure Mapping...")
        session.execute_write(ingest_infrastructure, all_ips)
        
        print(f"Ingesting {len(web_df)} Web Attacks...")
        session.execute_write(ingest_web_attacks, web_df)
        
        print(f"Ingesting {len(ssh_df)} SSH Attacks...")
        session.execute_write(ingest_ssh_attacks, ssh_df)
        
        print(f"Ingesting {len(packet_df)} Packet Logs (Beaconing/Lateral Movement)...")
        session.execute_write(ingest_packet_logs, packet_df)
        
        print(f"Ingesting {len(anomalies_df)} ML Anomalies (Campaigns)...")
        session.execute_write(ingest_campaigns, anomalies_df)

except Exception as e:
    print(f"Failed to connect or write to Neo4j: {e}")
finally:
    if 'driver' in locals():
        driver.close()

print(f"[{datetime.now()}] Ingestion Complete! Data is ready for visualization in local Neo4j Browser.")
