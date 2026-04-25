#!/usr/bin/env python3
import pyodbc
import os
import time

def read_config():
    config = {}
    try:
        with open('/home/adminuser/.env') as f:
            for line in f:
                line = line.strip()
                if '=' in line and not line.startswith('#'):
                    k, v = line.split('=', 1)
                    config[k.strip()] = v.strip()
        with open('/home/adminuser/.sql_pass') as f:
            config['SQL_PASS'] = f.read().strip()
    except Exception as e:
        print(f"Error reading config: {e}")
        return None
    return config

def init_db():
    cfg = read_config()
    if not cfg: return

    server = cfg['SQL_SERVER']
    database = cfg.get('SQL_DB', 'AttackLogsDB')
    username = cfg.get('SQL_USER', 'sqladmin')
    password = cfg['SQL_PASS']

    conn_str = (
        f'DRIVER={{ODBC Driver 17 for SQL Server}};'
        f'SERVER={server};DATABASE={database};'
        f'UID={username};PWD={password};'
        f'Encrypt=yes;TrustServerCertificate=no'
    )

    sql_file = '/home/adminuser/create_tables.sql'
    if not os.path.exists(sql_file):
        print(f"ERROR: {sql_file} not found")
        return

    print(f"Connecting to SQL Server: {server}...")
    
    for i in range(10):
        try:
            conn = pyodbc.connect(conn_str)
            cursor = conn.cursor()
            print("Connected successfully!")
            break
        except Exception as e:
            print(f"Waiting for SQL... ({i+1}/10): {e}")
            time.sleep(15)
    else:
        print("Failed to connect to SQL Server.")
        return

    print(f"Executing schema from {sql_file}...")
    try:
        with open(sql_file, 'r') as f:
            # SQL Server doesn't like some characters at the start of files
            # and we need to split by GO or just execute the whole block if no GO
            sql_script = f.read()
            
        # Basic split by GO (case insensitive)
        import re
        commands = re.split(r'\nGO\n', sql_script, flags=re.IGNORECASE)
        
        for cmd in commands:
            cmd = cmd.strip()
            if cmd:
                cursor.execute(cmd)
        
        conn.commit()
        print("Database schema applied successfully.")
    except Exception as e:
        print(f"Error applying schema: {e}")
        conn.rollback()
    finally:
        conn.close()

if __name__ == "__main__":
    init_db()
