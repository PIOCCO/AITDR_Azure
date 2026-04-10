-- Only creates if not exists
IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='WebAttacks' AND xtype='U')
CREATE TABLE WebAttacks (
    id              INT IDENTITY(1,1) PRIMARY KEY,
    attack_date     DATE NOT NULL,
    attack_time     DATETIME NOT NULL,
    attacker_ip     VARCHAR(45) NOT NULL,
    attack_type     VARCHAR(50) NOT NULL,
    url_path        VARCHAR(500),
    http_method     VARCHAR(10),
    status_code     INT,
    user_agent      VARCHAR(500),
    payload         VARCHAR(MAX),
    created_at      DATETIME DEFAULT GETDATE()
);

IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='SSHAttacks' AND xtype='U')
CREATE TABLE SSHAttacks (
    id              INT IDENTITY(1,1) PRIMARY KEY,
    attack_date     DATE NOT NULL,
    attack_time     DATETIME NOT NULL,
    attacker_ip     VARCHAR(45) NOT NULL,
    username_tried  VARCHAR(100),
    attack_type     VARCHAR(50),
    banned          BIT DEFAULT 0,
    created_at      DATETIME DEFAULT GETDATE()
);

IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='BotScans' AND xtype='U')
CREATE TABLE BotScans (
    id              INT IDENTITY(1,1) PRIMARY KEY,
    scan_date       DATE NOT NULL,
    attacker_ip     VARCHAR(45) NOT NULL,
    paths_scanned   INT DEFAULT 0,
    not_found_404   INT DEFAULT 0,
    user_agent      VARCHAR(500),
    created_at      DATETIME DEFAULT GETDATE()
);

IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='DailySummary' AND xtype='U')
CREATE TABLE DailySummary (
    id                  INT IDENTITY(1,1) PRIMARY KEY,
    summary_date        DATE NOT NULL UNIQUE,
    total_web_attacks   INT DEFAULT 0,
    total_ssh_attacks   INT DEFAULT 0,
    total_bot_scans     INT DEFAULT 0,
    unique_attackers    INT DEFAULT 0,
    sqli_attempts       INT DEFAULT 0,
    xss_attempts        INT DEFAULT 0,
    top_attacker_ip     VARCHAR(45),
    created_at          DATETIME DEFAULT GETDATE()
);

IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='PacketLogs' AND xtype='U')
CREATE TABLE PacketLogs (
    id              INT IDENTITY(1,1) PRIMARY KEY,
    captured_at     DATETIME DEFAULT GETDATE(),
    timestamp       DATETIME,
    src_ip          VARCHAR(45),
    dest_ip         VARCHAR(45),
    src_port        INT,
    dest_port       INT,
    protocol        VARCHAR(20),
    alert_signature VARCHAR(500),
    alert_severity  VARCHAR(20),
    http_url        VARCHAR(1000),
    http_method     VARCHAR(10),
    http_host       VARCHAR(200),
    http_user_agent VARCHAR(500),
    http_body       VARCHAR(MAX),
    payload         VARCHAR(MAX),
    packet_data     VARCHAR(MAX),
    flow_bytes_in   BIGINT,
    flow_bytes_out  BIGINT,
    dns_query       VARCHAR(500),
    tls_sni         VARCHAR(200),
    raw_json        VARCHAR(MAX)
);

IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='MLAnomalies' AND xtype='U')
CREATE TABLE MLAnomalies (
    id            INT IDENTITY(1,1) PRIMARY KEY,
    detected_at   DATETIME DEFAULT GETDATE(),
    time_window   DATETIME,
    anomaly_type  VARCHAR(50),
    event_count   INT,
    unique_ips    INT,
    anomaly_score FLOAT,
    confidence    FLOAT,
    model_used    VARCHAR(50),
    description   VARCHAR(1000),
    raw_features  VARCHAR(500)
);

-- Indexes
IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name='idx_web_attacks_date')
    CREATE INDEX idx_web_attacks_date ON WebAttacks(attack_date);
IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name='idx_web_attacks_ip')
    CREATE INDEX idx_web_attacks_ip ON WebAttacks(attacker_ip);
IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name='idx_web_attacks_type')
    CREATE INDEX idx_web_attacks_type ON WebAttacks(attack_type);
IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name='idx_ssh_attacks_date')
    CREATE INDEX idx_ssh_attacks_date ON SSHAttacks(attack_date);
IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name='idx_ssh_attacks_ip')
    CREATE INDEX idx_ssh_attacks_ip ON SSHAttacks(attacker_ip);
IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name='idx_bot_scans_date')
    CREATE INDEX idx_bot_scans_date ON BotScans(scan_date);
IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name='idx_daily_summary_date')
    CREATE INDEX idx_daily_summary_date ON DailySummary(summary_date);
IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name='idx_packet_src_ip')
    CREATE INDEX idx_packet_src_ip ON PacketLogs(src_ip);
IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name='idx_packet_timestamp')
    CREATE INDEX idx_packet_timestamp ON PacketLogs(timestamp);
IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name='idx_ml_anomalies_date')
    CREATE INDEX idx_ml_anomalies_date ON MLAnomalies(detected_at);
IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name='idx_ml_anomalies_type')
    CREATE INDEX idx_ml_anomalies_type ON MLAnomalies(anomaly_type);