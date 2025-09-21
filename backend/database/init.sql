-- CYBERLAB VULNERABLE DATABASE SCHEMA
-- WARNING: This configuration is INTENTIONALLY INSECURE
-- For educational purposes in cybersecurity
-- DO NOT use in production!

-- Create database if not exists
CREATE DATABASE IF NOT EXISTS cyberlab_vulnerable 
CHARACTER SET utf8mb4 
COLLATE utf8mb4_unicode_ci;

USE cyberlab_vulnerable;

-- USERS TABLE - VULNERABLE
-- Plaintext passwords, exposed structure, no protections
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    email VARCHAR(100) NOT NULL,
    password VARCHAR(255) NOT NULL, -- Plaintext passwords!
    password_hash VARCHAR(255), -- Some hashed, others not
    role ENUM('user', 'admin', 'moderator') DEFAULT 'user',
    status ENUM('active', 'inactive', 'banned') DEFAULT 'active',
    secret_token VARCHAR(255), -- Exposed secret token!
    api_key VARCHAR(255), -- Exposed API key!
    credit_card VARCHAR(20), -- Credit card without encryption!
    ssn VARCHAR(11), -- SSN without protection!
    salary DECIMAL(10,2), -- Sensitive information!
    notes TEXT, -- Field for stored XSS
    profile_pic VARCHAR(255),
    last_login DATETIME,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    -- Fields to demonstrate information disclosure
    internal_id VARCHAR(50), -- Internal ID that shouldn't be exposed
    debug_info TEXT, -- Debug information
    admin_notes TEXT -- Sensitive administrative notes
);

-- SESSIONS TABLE - VULNERABLE
-- Predictable session IDs, no proper expiration
CREATE TABLE IF NOT EXISTS sessions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    session_id VARCHAR(255) NOT NULL, -- Predictable IDs!
    user_id INT,
    data TEXT, -- Session data in plaintext!
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP, -- No expiration or too long!
    is_admin BOOLEAN DEFAULT FALSE,
    
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- POSTS/COMMENTS TABLE - VULNERABLE TO XSS
-- Stores HTML content without sanitization
CREATE TABLE IF NOT EXISTS posts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    title VARCHAR(255) NOT NULL,
    content TEXT, -- Unsanitized HTML/JS!
    html_content TEXT, -- Pure HTML - XSS risk!
    is_published BOOLEAN DEFAULT FALSE,
    views INT DEFAULT 0,
    likes INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    -- Additional vulnerable fields
    raw_input TEXT, -- User's original input
    sanitized_content TEXT, -- "Sanitized" but with flaws
    
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- UPLOADS TABLE - VULNERABLE
-- Allows any file type, predictable paths
CREATE TABLE IF NOT EXISTS file_uploads (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    original_filename VARCHAR(255), -- Original name preserved!
    stored_filename VARCHAR(255), -- Predictable path!
    file_path VARCHAR(500), -- Full path exposed!
    file_size INT,
    mime_type VARCHAR(100), -- Not properly validated!
    file_hash VARCHAR(64), -- File hash (may leak information)
    is_public BOOLEAN DEFAULT TRUE, -- Public by default!
    upload_ip VARCHAR(45),
    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- Dangerous metadata
    exif_data TEXT, -- EXIF data may contain location/device info!
    virus_scan_result VARCHAR(50) DEFAULT 'not_scanned', -- No antivirus!
    
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- LOGS TABLE - VULNERABLE
-- Stores logs in database (performance issue + security risk)
CREATE TABLE IF NOT EXISTS security_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    event_type VARCHAR(50),
    user_id INT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    request_data TEXT, -- Complete request including passwords!
    response_data TEXT, -- Complete response!
    sql_query TEXT, -- Executed SQL queries!
    payload TEXT, -- Attack payloads!
    success BOOLEAN,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- Vulnerable audit fields
    session_data TEXT, -- Complete session data!
    cookies TEXT, -- Captured cookies!
    headers TEXT -- Complete HTTP headers!
);

-- CONFIGURATION TABLE - VULNERABLE
-- System configurations accessible via SQL injection
CREATE TABLE IF NOT EXISTS system_config (
    id INT AUTO_INCREMENT PRIMARY KEY,
    config_key VARCHAR(100) UNIQUE,
    config_value TEXT, -- Sensitive values in plaintext!
    is_sensitive BOOLEAN DEFAULT FALSE,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- PRODUCTS/E-COMMERCE TABLE - VULNERABLE
-- To demonstrate IDOR (Insecure Direct Object References)
CREATE TABLE IF NOT EXISTS products (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255),
    description TEXT,
    price DECIMAL(10,2),
    stock INT DEFAULT 0,
    category_id INT,
    is_active BOOLEAN DEFAULT TRUE,
    
    -- Sensitive fields that may leak via IDOR
    cost_price DECIMAL(10,2), -- Cost price - sensitive!
    supplier_info TEXT, -- Supplier information!
    profit_margin DECIMAL(5,2), -- Profit margin!
    internal_notes TEXT, -- Internal notes!
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ORDERS TABLE - VULNERABLE TO IDOR
CREATE TABLE IF NOT EXISTS orders (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    total_amount DECIMAL(10,2),
    status ENUM('pending', 'processing', 'shipped', 'delivered', 'cancelled'),
    shipping_address TEXT,
    
    -- Vulnerable payment information
    payment_method VARCHAR(50),
    card_last_four VARCHAR(4), -- Card last 4 digits!
    transaction_id VARCHAR(100), -- Transaction ID!
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- TABLE FOR ADVANCED SQL INJECTION DEMONSTRATION
CREATE TABLE IF NOT EXISTS sensitive_data (
    id INT AUTO_INCREMENT PRIMARY KEY,
    data_type VARCHAR(50),
    classified_info TEXT, -- Classified information!
    access_level ENUM('public', 'restricted', 'confidential', 'top_secret'),
    owner_id INT,
    
    -- Data that demonstrates different types of injection
    json_data JSON, -- For NoSQL-style injection
    xml_data TEXT, -- For XXE attacks
    serialized_data BLOB, -- For deserialization attacks
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (owner_id) REFERENCES users(id)
);

-- CREATE VULNERABLE INDEXES
-- Indexes that may help attackers understand the structure

-- Index to facilitate SQL injection timing attacks
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_email ON users(email);

-- Index for password timing attacks
CREATE INDEX idx_users_password ON users(password);

-- Indexes that facilitate enumeration
CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_posts_user_id ON posts(user_id);
CREATE INDEX idx_orders_user_id ON orders(user_id);

-- CREATE VULNERABLE MYSQL USER
-- User with excessive privileges
CREATE USER IF NOT EXISTS 'vulnerable_user'@'%' IDENTIFIED BY 'weak123';
CREATE USER IF NOT EXISTS 'vulnerable_user'@'localhost' IDENTIFIED BY 'weak123';

-- DANGEROUS PRIVILEGES - DO NOT do in production!
GRANT ALL PRIVILEGES ON cyberlab_vulnerable.* TO 'vulnerable_user'@'%';
GRANT ALL PRIVILEGES ON cyberlab_vulnerable.* TO 'vulnerable_user'@'localhost';

-- Additional dangerous privileges
GRANT FILE ON *.* TO 'vulnerable_user'@'%'; -- Allows reading/writing files!
GRANT PROCESS ON *.* TO 'vulnerable_user'@'%'; -- View processes!
GRANT SUPER ON *.* TO 'vulnerable_user'@'%'; -- Super user privileges!

-- Apply changes
FLUSH PRIVILEGES;

-- VULNERABLE MYSQL CONFIGURATIONS
-- These configurations should be in my.cnf, but we include them here for documentation

-- SET GLOBAL general_log = 'ON'; -- Log all queries!
-- SET GLOBAL general_log_file = '/var/log/mysql/general.log';
-- SET GLOBAL slow_query_log = 'ON'; -- Log slow queries!
-- SET GLOBAL log_queries_not_using_indexes = 'ON';
-- SET GLOBAL sql_mode = ''; -- Disables validations!

-- Show dangerous information (for logs)
SELECT 'Database schema created successfully' as status;
SELECT USER() as current_user;
SELECT DATABASE() as current_database;
SELECT VERSION() as mysql_version;

-- Creation log (for educational audit)
INSERT INTO security_logs (event_type, request_data, success, created_at) VALUES 
('DATABASE_INIT', 'Vulnerable database schema created', TRUE, NOW());