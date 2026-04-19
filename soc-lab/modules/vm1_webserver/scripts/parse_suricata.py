#!/usr/bin/env python3
# ============================================
# parse_suricata.py - PRODUCTION V3
# Handles: rotation, batching, filtering, dedup, transactions
# ============================================

import json
import pyodbc
from datetime import datetime, timezone
import os
import hashlib
from typing import Dict, List, Optional, Tuple
import sys
import time
import logging

# ============================================
# CONFIGURATION
# ============================================
BATCH_SIZE = 1000  # Commit every 1000 rows
MAX_RETRIES = 3
RETRY_DELAY = 5

# Only keep high-value event types
KEEP_EVENT_TYPES = {
    'alert': True,   # Critical - always keep
    'http': True,    # Keep - web attacks
    'tls': True,     # Keep - C2 detection
    'dns': False,    # Skip - too noisy
    'flow': False,   # Skip - extremely noisy
    'stats': False,  # Skip - not security relevant
    'fileinfo': False,
    'ssh': False,
    'smb': False,
}

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/suricata_parser.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ============================================
# CONFIG MANAGEMENT
# ============================================
def read_config() -> Dict[str, str]:
    """Read configuration from secure files"""
    config = {}
    
    env_path = '/home/adminuser/.env'
    if not os.path.exists(env_path):
        raise FileNotFoundError(f"Config not found: {env_path}")
    
    with open(env_path) as f:
        for line in f:
            line = line.strip()
            if '=' in line and not line.startswith('#'):
                k, v = line.split('=', 1)
                config[k.strip()] = v.strip()
    
    pass_path = '/home/adminuser/.sql_pass'
    with open(pass_path) as f:
        config['SQL_PASS'] = f.read().strip()
    
    return config

# ============================================
# OFFSET MANAGEMENT WITH ROTATION HANDLING
# ============================================
def get_file_metadata(filepath: str) -> Tuple[int, int]:
    """Get (inode, size) for rotation detection"""
    try:
        stat = os.stat(filepath)
        return (stat.st_ino, stat.st_size)
    except OSError as e:
        logger.error(f"Cannot stat {filepath}: {e}")
        return (0, 0)

def read_offset() -> Tuple[int, int, int]:
    """
    Read saved state: (inode, offset, last_position)
    Returns (saved_inode, saved_offset, last_known_position)
    """
    offset_file = "/home/adminuser/suricata_offset.txt"
    
    if not os.path.exists(offset_file):
        return (0, 0, 0)
    
    try:
        with open(offset_file, 'r') as f:
            data = f.read().strip()
            parts = data.split(':')
            if len(parts) == 2:
                return (int(parts[0]), int(parts[1]), int(parts[1]))
            elif len(parts) == 3:
                return (int(parts[0]), int(parts[1]), int(parts[2]))
    except (ValueError, IOError) as e:
        logger.warning(f"Failed to read offset: {e}")
    
    return (0, 0, 0)

def write_offset(inode: int, offset: int, position: int = None) -> None:
    """Save current state: inode:offset:position"""
    offset_file = "/home/adminuser/suricata_offset.txt"
    pos = position if position is not None else offset
    
    with open(offset_file, 'w') as f:
        f.write(f"{inode}:{offset}:{pos}")

def validate_offset(filepath: str, offset: int, inode: int, saved_inode: int) -> int:
    """
    Validate offset after rotation or file changes
    Returns corrected offset
    """
    current_size = os.path.getsize(filepath)
    
    # Case 1: Log rotated
    if saved_inode != 0 and saved_inode != inode:
        logger.info(f"Log rotated (inode {saved_inode} -> {inode}), resetting offset")
        return 0
    
    # Case 2: Offset beyond file size
    if offset > current_size:
        logger.warning(f"Offset {offset} > file size {current_size}, resetting")
        return 0
    
    # Case 3: File truncated but same inode
    if offset > 0 and current_size < offset:
        logger.warning(f"File truncated, resetting offset")
        return 0
    
    return offset

# ============================================
# DATABASE CONNECTION
# ============================================
def connect_to_sql(config: Dict[str, str]) -> Optional[pyodbc.Connection]:
    """Connect with retry logic"""
    for attempt in range(MAX_RETRIES):
        try:
            conn_str = (
                f'DRIVER={{ODBC Driver 17 for SQL Server}};'
                f'SERVER={config["SQL_SERVER"]};'
                f'DATABASE={config["SQL_DB"]};'
                f'UID={config["SQL_USER"]};'
                f'PWD={config["SQL_PASS"]};'
                f'Encrypt=yes;TrustServerCertificate=no;'
                f'Connection Timeout=30'
            )
            
            conn = pyodbc.connect(conn_str, timeout=30, autocommit=False)
            logger.info("Connected to SQL Server")
            return conn
            
        except Exception as e:
            logger.error(f"Connection attempt {attempt+1} failed: {e}")
            if attempt < MAX_RETRIES - 1:
                time.sleep(RETRY_DELAY)
    
    return None

# ============================================
# EVENT PROCESSING
# ============================================
def parse_timestamp(timestamp_str: str) -> datetime:
    """Parse timestamp preserving timezone and milliseconds"""
    if not timestamp_str:
        return datetime.now(timezone.utc)
    
    # Try formats in order of completeness
    formats = [
        '%Y-%m-%dT%H:%M:%S.%f%z',  # Full with tz
        '%Y-%m-%dT%H:%M:%S.%fZ',   # UTC with microseconds
        '%Y-%m-%dT%H:%M:%S.%f',    # Microseconds no tz
        '%Y-%m-%dT%H:%M:%SZ',      # UTC second precision
        '%Y-%m-%dT%H:%M:%S',       # No tz, no ms
    ]
    
    for fmt in formats:
        try:
            dt = datetime.strptime(timestamp_str, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    
    logger.warning(f"Unparseable timestamp: {timestamp_str}")
    return datetime.now(timezone.utc)

def should_keep_event(event_type: str) -> bool:
    """Filter noisy event types"""
    return KEEP_EVENT_TYPES.get(event_type, False)

def process_event(event: Dict, raw_line: str) -> Optional[Tuple]:
    """
    Process single event, return tuple for batch insert
    Returns None if event should be skipped
    """
    event_type = event.get('event_type', '')
    
    # Apply filtering
    if not should_keep_event(event_type):
        return None
    
    # Extract common fields
    src_ip = event.get('src_ip', '')
    dest_ip = event.get('dest_ip', '')
    src_port = event.get('src_port', 0)
    dest_port = event.get('dest_port', 0)
    protocol = event.get('proto', '')
    ts = parse_timestamp(event.get('timestamp', ''))
    
    # Initialize optional fields
    alert_sig = alert_sev = ''
    http_url = http_method = http_host = http_ua = http_body = ''
    payload = packet_data = ''
    bytes_in = bytes_out = 0
    dns_query = tls_sni = ''
    
    # Extract event-specific data
    if event_type == 'alert':
        a = event.get('alert', {})
        alert_sig = a.get('signature', '')[:500]
        alert_sev = str(a.get('severity', ''))
        payload = event.get('payload_printable', '') or ''
        packet_data = event.get('packet', '') or ''
        
    elif event_type == 'http':
        h = event.get('http', {})
        http_url = h.get('url', '')[:1000]
        http_method = h.get('http_method', '')[:10]
        http_host = h.get('hostname', '')[:200]
        http_ua = h.get('http_user_agent', '')[:500]
        http_body = h.get('http_request_body_printable', '') or ''
        
    elif event_type == 'tls':
        tls_sni = event.get('tls', {}).get('sni', '')[:200]
    
    # Create deduplication hash
    hash_input = f"{ts.isoformat()}|{src_ip}|{dest_ip}|{src_port}|{dest_port}|{event_type}"
    event_hash = hashlib.md5(hash_input.encode()).hexdigest()[:32]
    
    return (
        event_hash, ts,
        src_ip, dest_ip, src_port, dest_port,
        protocol, event_type,
        alert_sig, alert_sev,
        http_url, http_method, http_host, http_ua, http_body,
        payload, packet_data,
        bytes_in, bytes_out,
        dns_query, tls_sni,
        raw_line,  # Full JSON without truncation
    )

def batch_insert(cursor, batch: List[Tuple]) -> int:
    """Execute batch insert with deduplication"""
    if not batch:
        return 0
    
    sql = """
        IF NOT EXISTS (
            SELECT 1 FROM PacketLogs 
            WHERE event_hash = ? AND timestamp = ?
        )
        INSERT INTO PacketLogs (
            event_hash, timestamp,
            src_ip, dest_ip, src_port, dest_port,
            protocol, event_type,
            alert_signature, alert_severity,
            http_url, http_method, http_host, http_user_agent, http_body,
            payload, packet_data,
            flow_bytes_in, flow_bytes_out,
            dns_query, tls_sni,
            raw_json
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """
    
    try:
        cursor.executemany(sql, batch)
        return len(batch)
    except Exception as e:
        logger.error(f"Batch insert failed: {e}")
        # Try one by one to isolate bad row
        success = 0
        for row in batch:
            try:
                cursor.execute(sql, row)
                success += 1
            except Exception as row_error:
                logger.error(f"Failed to insert row: {row_error}")
        return success

# ============================================
# MAIN PROCESSING LOOP
# ============================================
def main():
    # Load configuration
    try:
        config = read_config()
        logger.info("Configuration loaded")
    except Exception as e:
        logger.error(f"Failed to load config: {e}")
        sys.exit(1)
    
    eve_log = "/var/log/suricata/eve.json"
    if not os.path.exists(eve_log):
        logger.info(f"{eve_log} not found, skipping")
        sys.exit(0)
    
    # Handle log rotation
    current_inode, current_size = get_file_metadata(eve_log)
    saved_inode, saved_offset, last_pos = read_offset()
    
    # Validate and correct offset
    start_offset = validate_offset(eve_log, saved_offset, current_inode, saved_inode)
    
    if start_offset != saved_offset:
        logger.warning(f"Offset corrected: {saved_offset} -> {start_offset}")
        write_offset(current_inode, start_offset)
    
    # Connect to database
    conn = connect_to_sql(config)
    if not conn:
        logger.error("Cannot proceed without database connection")
        sys.exit(1)
    
    cursor = conn.cursor()
    
    inserted = 0
    skipped_filter = 0
    skipped_error = 0
    batch = []
    lines_processed = 0
    checkpoint = time.time()
    
    logger.info(f"Starting parse from offset {start_offset} (inode {current_inode})")
    
    try:
        with open(eve_log, 'r') as f:
            f.seek(start_offset)
            
            for line in f:
                lines_processed += 1
                line = line.strip()
                if not line:
                    continue
                
                try:
                    event = json.loads(line)
                    processed = process_event(event, line)
                    
                    if processed is None:
                        skipped_filter += 1
                        continue
                    
                    batch.append(processed)
                    
                    # Execute batch when full
                    if len(batch) >= BATCH_SIZE:
                        batch_inserted = batch_insert(cursor, batch)
                        conn.commit()
                        inserted += batch_inserted
                        skipped_error += (len(batch) - batch_inserted)
                        
                        logger.info(f"Progress: {inserted} inserted, {skipped_filter} filtered, "
                                  f"{skipped_error} errors, {lines_processed} lines")
                        batch = []
                    
                    # Update position periodically
                    if lines_processed % 100 == 0:
                        current_pos = f.tell()
                        write_offset(current_inode, current_pos, current_pos)
                    
                except json.JSONDecodeError as e:
                    skipped_error += 1
                    logger.warning(f"Invalid JSON at line {lines_processed}: {e}")
                    continue
                except Exception as e:
                    skipped_error += 1
                    logger.error(f"Unexpected error processing line {lines_processed}: {e}", exc_info=True)
                    continue
                
                # Performance logging every 30 seconds
                if time.time() - checkpoint > 30:
                    rate = lines_processed / (time.time() - checkpoint)
                    logger.info(f"Processing rate: {rate:.1f} lines/sec")
                    checkpoint = time.time()
            
            # Final batch
            if batch:
                batch_inserted = batch_insert(cursor, batch)
                conn.commit()
                inserted += batch_inserted
                skipped_error += (len(batch) - batch_inserted)
            
            # Save final position
            final_pos = f.tell()
            write_offset(current_inode, final_pos, final_pos)
            
    except Exception as e:
        logger.error(f"Fatal error in main loop: {e}", exc_info=True)
        conn.rollback()
    finally:
        conn.close()
    
    logger.info(f"COMPLETED - Inserted: {inserted}, Filtered: {skipped_filter}, "
                f"Errors: {skipped_error}, Lines: {lines_processed}")

if __name__ == "__main__":
    main()