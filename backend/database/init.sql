-- 🚨 CYBERLAB VULNERABLE DATABASE SCHEMA
-- ⚠️ Esta configuração é INTENCIONALMENTE INSEGURA
-- 🎓 Para fins educacionais em segurança cibernética
-- 🚨 NÃO usar em produção!

-- Criar database se não existir
CREATE DATABASE IF NOT EXISTS cyberlab_vulnerable 
CHARACTER SET utf8mb4 
COLLATE utf8mb4_unicode_ci;

USE cyberlab_vulnerable;

-- 🚨 TABELA DE USUÁRIOS - VULNERÁVEL
-- Senhas em texto plano, estrutura exposta, sem proteções
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    email VARCHAR(100) NOT NULL,
    password VARCHAR(255) NOT NULL, -- ⚠️ Senhas em texto plano!
    password_hash VARCHAR(255), -- Algumas hashadas, outras não
    role ENUM('user', 'admin', 'moderator') DEFAULT 'user',
    status ENUM('active', 'inactive', 'banned') DEFAULT 'active',
    secret_token VARCHAR(255), -- ⚠️ Token secreto exposto!
    api_key VARCHAR(255), -- ⚠️ API key exposta!
    credit_card VARCHAR(20), -- ⚠️ Cartão de crédito sem criptografia!
    ssn VARCHAR(11), -- ⚠️ SSN sem proteção!
    salary DECIMAL(10,2), -- ⚠️ Informação sensível!
    notes TEXT, -- Campo para XSS stored
    profile_pic VARCHAR(255),
    last_login DATETIME,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    -- Campos para demonstrar information disclosure
    internal_id VARCHAR(50), -- ID interno que não deveria ser exposto
    debug_info TEXT, -- Informações de debug
    admin_notes TEXT -- Notas administrativas sensíveis
);

-- 🚨 TABELA DE SESSÕES - VULNERÁVEL
-- Session IDs previsíveis, sem expiração adequada
CREATE TABLE IF NOT EXISTS sessions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    session_id VARCHAR(255) NOT NULL, -- ⚠️ IDs previsíveis!
    user_id INT,
    data TEXT, -- ⚠️ Dados de sessão em texto plano!
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP, -- ⚠️ Sem expiração ou muito longa!
    is_admin BOOLEAN DEFAULT FALSE,
    
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- 🚨 TABELA DE POSTS/COMENTÁRIOS - VULNERÁVEL A XSS
-- Armazena conteúdo HTML sem sanitização
CREATE TABLE IF NOT EXISTS posts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    title VARCHAR(255) NOT NULL,
    content TEXT, -- ⚠️ HTML/JS não sanitizado!
    html_content TEXT, -- ⚠️ HTML puro - XSS risk!
    is_published BOOLEAN DEFAULT FALSE,
    views INT DEFAULT 0,
    likes INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    -- Campos vulneráveis adicionais
    raw_input TEXT, -- Input original do usuário
    sanitized_content TEXT, -- "Sanitizado" mas com falhas
    
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- 🚨 TABELA DE UPLOADS - VULNERÁVEL
-- Permite qualquer tipo de arquivo, paths previsíveis
CREATE TABLE IF NOT EXISTS file_uploads (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    original_filename VARCHAR(255), -- ⚠️ Nome original preservado!
    stored_filename VARCHAR(255), -- ⚠️ Path previsível!
    file_path VARCHAR(500), -- ⚠️ Path completo exposto!
    file_size INT,
    mime_type VARCHAR(100), -- ⚠️ Não validado adequadamente!
    file_hash VARCHAR(64), -- Hash do arquivo (pode vazar informações)
    is_public BOOLEAN DEFAULT TRUE, -- ⚠️ Público por padrão!
    upload_ip VARCHAR(45),
    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- Metadata perigosa
    exif_data TEXT, -- ⚠️ EXIF data pode conter localização/device info!
    virus_scan_result VARCHAR(50) DEFAULT 'not_scanned', -- ⚠️ Sem antivírus!
    
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- 🚨 TABELA DE LOGS - VULNERÁVEL
-- Armazena logs em database (performance issue + security risk)
CREATE TABLE IF NOT EXISTS security_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    event_type VARCHAR(50),
    user_id INT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    request_data TEXT, -- ⚠️ Request completo incluindo senhas!
    response_data TEXT, -- ⚠️ Response completo!
    sql_query TEXT, -- ⚠️ Queries SQL executadas!
    payload TEXT, -- ⚠️ Payloads de ataques!
    success BOOLEAN,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- Campos de auditoria vulneráveis
    session_data TEXT, -- ⚠️ Dados de sessão completos!
    cookies TEXT, -- ⚠️ Cookies capturados!
    headers TEXT -- ⚠️ Headers HTTP completos!
);

-- 🚨 TABELA DE CONFIGURAÇÕES - VULNERÁVEL
-- Configurações do sistema acessíveis via SQL injection
CREATE TABLE IF NOT EXISTS system_config (
    id INT AUTO_INCREMENT PRIMARY KEY,
    config_key VARCHAR(100) UNIQUE,
    config_value TEXT, -- ⚠️ Valores sensíveis em texto plano!
    is_sensitive BOOLEAN DEFAULT FALSE,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- 🚨 TABELA DE PRODUTOS/E-COMMERCE - VULNERÁVEL
-- Para demonstrar IDOR (Insecure Direct Object References)
CREATE TABLE IF NOT EXISTS products (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255),
    description TEXT,
    price DECIMAL(10,2),
    stock INT DEFAULT 0,
    category_id INT,
    is_active BOOLEAN DEFAULT TRUE,
    
    -- Campos sensíveis que podem vazar via IDOR
    cost_price DECIMAL(10,2), -- ⚠️ Preço de custo - sensível!
    supplier_info TEXT, -- ⚠️ Informações do fornecedor!
    profit_margin DECIMAL(5,2), -- ⚠️ Margem de lucro!
    internal_notes TEXT, -- ⚠️ Notas internas!
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 🚨 TABELA DE PEDIDOS - VULNERÁVEL A IDOR
CREATE TABLE IF NOT EXISTS orders (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    total_amount DECIMAL(10,2),
    status ENUM('pending', 'processing', 'shipped', 'delivered', 'cancelled'),
    shipping_address TEXT,
    
    -- Informações de pagamento vulneráveis
    payment_method VARCHAR(50),
    card_last_four VARCHAR(4), -- ⚠️ Últimos 4 dígitos do cartão!
    transaction_id VARCHAR(100), -- ⚠️ ID da transação!
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- 🚨 TABELA PARA DEMONSTRAR SQL INJECTION AVANÇADA
CREATE TABLE IF NOT EXISTS sensitive_data (
    id INT AUTO_INCREMENT PRIMARY KEY,
    data_type VARCHAR(50),
    classified_info TEXT, -- ⚠️ Informações classificadas!
    access_level ENUM('public', 'restricted', 'confidential', 'top_secret'),
    owner_id INT,
    
    -- Dados que demonstram diferentes tipos de injection
    json_data JSON, -- Para NoSQL-style injection
    xml_data TEXT, -- Para XXE attacks
    serialized_data BLOB, -- Para deserialization attacks
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (owner_id) REFERENCES users(id)
);

-- 🚨 CRIAR ÍNDICES VULNERÁVEIS
-- Índices que podem ajudar atacantes a entender a estrutura

-- Index para facilitar SQL injection timing attacks
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_email ON users(email);

-- Index para password timing attacks
CREATE INDEX idx_users_password ON users(password);

-- Indexes que facilitam enumeration
CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_posts_user_id ON posts(user_id);
CREATE INDEX idx_orders_user_id ON orders(user_id);

-- 🚨 CRIAR USUÁRIO MYSQL VULNERÁVEL
-- Usuário com privilégios excessivos
CREATE USER IF NOT EXISTS 'vulnerable_user'@'%' IDENTIFIED BY 'weak123';
CREATE USER IF NOT EXISTS 'vulnerable_user'@'localhost' IDENTIFIED BY 'weak123';

-- ⚠️ PRIVILÉGIOS PERIGOSOS - NÃO fazer em produção!
GRANT ALL PRIVILEGES ON cyberlab_vulnerable.* TO 'vulnerable_user'@'%';
GRANT ALL PRIVILEGES ON cyberlab_vulnerable.* TO 'vulnerable_user'@'localhost';

-- Privilégios adicionais perigosos
GRANT FILE ON *.* TO 'vulnerable_user'@'%'; -- ⚠️ Permite ler/escrever arquivos!
GRANT PROCESS ON *.* TO 'vulnerable_user'@'%'; -- ⚠️ Ver processos!
GRANT SUPER ON *.* TO 'vulnerable_user'@'%'; -- ⚠️ Privilégios de super user!

-- Aplicar mudanças
FLUSH PRIVILEGES;

-- 🚨 CONFIGURAÇÕES MYSQL VULNERÁVEIS
-- Estas configurações devem estar no my.cnf, mas incluímos aqui para documentação

-- SET GLOBAL general_log = 'ON'; -- ⚠️ Log todas as queries!
-- SET GLOBAL general_log_file = '/var/log/mysql/general.log';
-- SET GLOBAL slow_query_log = 'ON'; -- ⚠️ Log queries lentas!
-- SET GLOBAL log_queries_not_using_indexes = 'ON';
-- SET GLOBAL sql_mode = ''; -- ⚠️ Desabilita validações!

-- Mostrar informações perigosas (para logs)
SELECT 'Database schema created successfully' as status;
SELECT USER() as current_user;
SELECT DATABASE() as current_database;
SELECT VERSION() as mysql_version;

-- Log da criação (para auditoria educacional)
INSERT INTO security_logs (event_type, request_data, success, created_at) VALUES 
('DATABASE_INIT', 'Vulnerable database schema created', TRUE, NOW());