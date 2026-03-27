-- ============================================
-- AITDR Attack Logs Database Schema
-- Run this after SQL Database is created
-- ============================================

-- Web Attacks Table (DVWA logs)
CREATE TABLE WebAttacks (
    id              INT IDENTITY(1,1) PRIMARY KEY,
    attack_date     DATE NOT NULL,
    attack_time     DATETIME NOT NULL,
    attacker_ip     VARCHAR(45) NOT NULL,
    attack_type     VARCHAR(50) NOT NULL,  -- SQLi, XSS, PathTraversal, BruteForce
    url_path        VARCHAR(500),
    http_method     VARCHAR(10),
    status_code     INT,
    user_agent      VARCHAR(500),
    payload         VARCHAR(MAX),
    created_at      DATETIME DEFAULT GETDATE()
);

-- SSH Attacks Table
CREATE TABLE SSHAttacks (
    id              INT IDENTITY(1,1) PRIMARY KEY,
    attack_date     DATE NOT NULL,
    attack_time     DATETIME NOT NULL,
    attacker_ip     VARCHAR(45) NOT NULL,
    username_tried  VARCHAR(100),
    attack_type     VARCHAR(50),  -- InvalidUser, BruteForce, BadProtocol
    banned          BIT DEFAULT 0,
    created_at      DATETIME DEFAULT GETDATE()
);

-- Bot Scanning Table
CREATE TABLE BotScans (
    id              INT IDENTITY(1,1) PRIMARY KEY,
    scan_date       DATE NOT NULL,
    attacker_ip     VARCHAR(45) NOT NULL,
    paths_scanned   INT DEFAULT 0,
    not_found_404   INT DEFAULT 0,
    user_agent      VARCHAR(500),
    created_at      DATETIME DEFAULT GETDATE()
);

-- Daily Summary Table (for Power BI)
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

-- ============================================
-- INDEXES for faster Power BI queries
-- ============================================
CREATE INDEX idx_web_attacks_date ON WebAttacks(attack_date);
CREATE INDEX idx_web_attacks_ip ON WebAttacks(attacker_ip);
CREATE INDEX idx_web_attacks_type ON WebAttacks(attack_type);
CREATE INDEX idx_ssh_attacks_date ON SSHAttacks(attack_date);
CREATE INDEX idx_ssh_attacks_ip ON SSHAttacks(attacker_ip);
CREATE INDEX idx_bot_scans_date ON BotScans(scan_date);
CREATE INDEX idx_daily_summary_date ON DailySummary(summary_date);
