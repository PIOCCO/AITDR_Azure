#!/usr/bin/env python3
# ============================================
# parse_logs.py
# Reads credentials from secure .env file
# NO hardcoded secrets
# ============================================

import pyodbc
from datetime import datetime
import os
import hashlib
import urllib.request
import json

# ============================================
# GEOIP CACHE (minimize API calls)
# ============================================
GEO_CACHE = {}

def get_geoip(ip):
    if ip in GEO_CACHE: return GEO_CACHE[ip]
    if ip in ['127.0.0.1', 'localhost'] or ip.startswith('10.') or ip.startswith('172.'):
        return "Internal", "Internal", 0, 0
    try:
        # Use free ip-api.com (Rate limited to 45 requests per minute)
        with urllib.request.urlopen(f"http://ip-api.com/json/{ip}?fields=status,country,city,lat,lon", timeout=1) as response:
            data = json.loads(response.read().decode())
            if data['status'] == 'success':
                res = (data['country'], data['city'], data['lat'], data['lon'])
                GEO_CACHE[ip] = res
                return res
    except:
        pass
    return "Unknown", "Unknown", 0, 0

# ============================================
# READ CONFIG FROM SECURE FILES
# ============================================
def read_config():
    config = {}
    try:
        with open('/home/adminuser/.env') as f:
            for line in f:
                line = line.strip()
                if '=' in line and not line.startswith('#'):
                    k, v = line.split('=', 1)
                    config[k.strip()] = v.strip()
    except Exception as e:
        print(f"Error reading .env: {e}")
        raise

    try:
        with open('/home/adminuser/.sql_pass') as f:
            config['SQL_PASS'] = f.read().strip()
    except Exception as e:
        print(f"Error reading .sql_pass: {e}")
        raise

    return config

import hashlib

def log_hash(line):
    return hashlib.md5(line.encode()).hexdigest()[:16]



cfg = read_config()

SQL_SERVER = cfg.get('SQL_SERVER', '')
SQL_DB     = cfg.get('SQL_DB', 'AttackLogsDB')
SQL_USER   = cfg.get('SQL_USER', 'sqladmin')
SQL_PASS   = cfg.get('SQL_PASS', '')

if not SQL_SERVER or not SQL_PASS:
    print("ERROR: Missing SQL credentials")
    exit(1)

# ============================================
# CONNECT TO SQL
# ============================================
try:
    conn = pyodbc.connect(
        f'DRIVER={{ODBC Driver 17 for SQL Server}};'
        f'SERVER={SQL_SERVER};'
        f'DATABASE={SQL_DB};'
        f'UID={SQL_USER};'
        f'PWD={SQL_PASS};'
        f'Encrypt=yes;TrustServerCertificate=no'
    )
    cursor = conn.cursor()
except Exception as e:
    print(f"SQL connection error: {e}")
    exit(1)

# ============================================
# PARSE APACHE ACCESS LOG
# ============================================
web_count  = 0
bot_count  = 0
sqli_count = 0
xss_count  = 0

try:
    with open('/tmp/apache_access.log') as f:
        for line in f:
            parts = line.split()
            if len(parts) < 9:
                continue

            ip         = parts[0]
            method     = parts[5].strip('"')
            url        = parts[6]
            status     = parts[8]
            user_agent = ' '.join(parts[11:]).strip('"') if len(parts) > 11 else ''

            try:
                status_code = int(status)
            except:
                continue

            url_lower = url.lower()
            if any(x in url_lower for x in ['select', 'union', 'insert', 'drop', 'exec']):
                attack_type = 'SQLi'
                sqli_count += 1
            elif any(x in url_lower for x in ['script', 'alert', 'onerror', 'onload']):
                attack_type = 'XSS'
                xss_count += 1
            elif '../' in url:
                attack_type = 'PathTraversal'
            elif 'mozi' in url_lower or 'setup.cgi' in url_lower:
                attack_type = 'Botnet'
                bot_count += 1
            elif method == 'POST':
                attack_type = 'BruteForce'
            else:
                attack_type = 'Scan'

            # Calculate event_hash for deduplication
            hash_input = f"{ip}|{method}|{url}|{status}|{user_agent}"
            event_hash = hashlib.md5(hash_input.encode()).hexdigest()[:32]

            try:
                # Check for duplicate using event_hash
                cursor.execute(
                    "SELECT COUNT(*) FROM WebAttacks WHERE event_hash=?",
                    event_hash
                )

                if cursor.fetchone()[0] == 0:
                    country, city, lat, lon = get_geoip(ip)
                    cursor.execute("""
                        INSERT INTO WebAttacks
                            (event_hash, attack_date, attack_time, attacker_ip, attack_type,
                            url_path, http_method, status_code, user_agent, country, city, latitude, longitude)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                        event_hash, datetime.now().date(), datetime.now(),
                        ip, attack_type, url[:500], method, status_code, user_agent[:500],
                        country, city, lat, lon
                    )
                    web_count += 1
            except Exception as e:
                continue

except FileNotFoundError:
    print("Apache log not found - skipping web attack parsing")

# ============================================
# PARSE SSH AUTH LOG
# ============================================
ssh_count = 0
try:
    with open('/var/log/auth.log') as f:
        for line in f:
            if 'Invalid user' in line or 'Connection closed by invalid' in line:
                parts = line.split()
                try:
                    ip       = parts[9] if 'Invalid user' in line else parts[7]
                    username = parts[7] if 'Invalid user' in line else 'unknown'
                    
                    # Calculate event_hash for SSH
                    hash_input = f"SSH|{ip}|{username}|{line[:50]}"
                    event_hash = hashlib.md5(hash_input.encode()).hexdigest()[:32]

                    # Check for duplicate
                    cursor.execute("SELECT COUNT(*) FROM SSHAttacks WHERE event_hash=?", event_hash)
                    
                    if cursor.fetchone()[0] == 0:
                        country, city, lat, lon = get_geoip(ip)
                        cursor.execute("""
                            INSERT INTO SSHAttacks
                                (event_hash, attack_date, attack_time, attacker_ip, username_tried, attack_type,
                                country, city, latitude, longitude)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                            event_hash, datetime.now().date(), datetime.now(),
                            ip, username, 'InvalidUser',
                            country, city, lat, lon
                        )
                        ssh_count += 1
                except:
                    continue
except Exception as e:
    print(f"SSH log parse error: {e}")

# ============================================
# DAILY SUMMARY
# ============================================
try:
    cursor.execute("""
        MERGE DailySummary AS target
        USING (SELECT ? AS summary_date) AS source
        ON target.summary_date = source.summary_date
        WHEN MATCHED THEN
            UPDATE SET
                total_web_attacks = ?,
                total_ssh_attacks = ?,
                total_bot_scans   = ?,
                sqli_attempts     = ?,
                xss_attempts      = ?
        WHEN NOT MATCHED THEN
            INSERT (summary_date, total_web_attacks, total_ssh_attacks,
                    total_bot_scans, sqli_attempts, xss_attempts)
            VALUES (?, ?, ?, ?, ?, ?);
    """,
        datetime.now().date(),
        web_count, ssh_count, bot_count, sqli_count, xss_count,
        datetime.now().date(),
        web_count, ssh_count, bot_count, sqli_count, xss_count
    )
except Exception as e:
    print(f"Summary update error: {e}")

# ============================================
# DATA RETENTION (30 DAY CLEANUP)
# ============================================
try:
    print("Running 30-day data retention cleanup...")
    cursor.execute("DELETE FROM WebAttacks WHERE attack_date < DATEADD(day, -30, GETDATE())")
    cursor.execute("DELETE FROM SSHAttacks WHERE attack_date < DATEADD(day, -30, GETDATE())")
    cursor.execute("DELETE FROM PacketLogs WHERE timestamp < DATEADD(day, -30, GETDATE())")
except Exception as e:
    print(f"Retention cleanup error: {e}")

conn.commit()
conn.close()
print(f"[{datetime.now()}] Done: {web_count} web, {ssh_count} SSH attacks inserted")
