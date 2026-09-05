-- MEGATRON MariaDB schema
-- Loaded by docker-compose's mariadb init phase (mounted at /docker-entrypoint-initdb.d/)
-- Also usable stand-alone for bare-metal installs:
--   sudo mariadb < docs/schema.sql

CREATE DATABASE IF NOT EXISTS megatron
    DEFAULT CHARACTER SET utf8mb4
    DEFAULT COLLATE utf8mb4_unicode_ci;

CREATE USER IF NOT EXISTS 'megatron'@'%' IDENTIFIED BY '123';
GRANT ALL PRIVILEGES ON megatron.* TO 'megatron'@'%';
CREATE USER IF NOT EXISTS 'megatron'@'localhost' IDENTIFIED BY '123';
GRANT ALL PRIVILEGES ON megatron.* TO 'megatron'@'localhost';
FLUSH PRIVILEGES;

USE megatron;

CREATE TABLE IF NOT EXISTS history (
    sl_no     INT AUTO_INCREMENT PRIMARY KEY,
    target    VARCHAR(255) NOT NULL,
    scan_date DATETIME NOT NULL,
    status    VARCHAR(50) DEFAULT 'active'
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    sl_no       INT,
    vuln_name   TEXT,
    severity    VARCHAR(50),
    port        VARCHAR(20),
    service     VARCHAR(100),
    description TEXT,
    FOREIGN KEY (sl_no) REFERENCES history(sl_no)
);

CREATE TABLE IF NOT EXISTS fixes (
    id       INT AUTO_INCREMENT PRIMARY KEY,
    sl_no    INT,
    vuln_id  INT,
    fix_text TEXT,
    source   VARCHAR(50),
    FOREIGN KEY (sl_no)   REFERENCES history(sl_no),
    FOREIGN KEY (vuln_id) REFERENCES vulnerabilities(id)
);

CREATE TABLE IF NOT EXISTS exploits_attempted (
    id           INT AUTO_INCREMENT PRIMARY KEY,
    sl_no        INT,
    exploit_name TEXT,
    tool_used    TEXT,
    payload      LONGTEXT,
    result       TEXT,
    notes        TEXT,
    FOREIGN KEY (sl_no) REFERENCES history(sl_no)
);

CREATE TABLE IF NOT EXISTS summary (
    id           INT AUTO_INCREMENT PRIMARY KEY,
    sl_no        INT,
    raw_scan     LONGTEXT,
    ai_analysis  LONGTEXT,
    risk_level   VARCHAR(50),
    generated_at DATETIME,
    FOREIGN KEY (sl_no) REFERENCES history(sl_no)
);
