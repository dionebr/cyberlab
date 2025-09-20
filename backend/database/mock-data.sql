-- 🚨 DADOS VULNERÁVEIS PARA TESTES
-- ⚠️ Estes dados são INTENCIONALMENTE INSEGUROS
-- 🎓 Para demonstração de vulnerabilidades
-- 🚨 NÃO usar dados reais!

USE cyberlab_vulnerable;

-- 🚨 INSERIR USUÁRIOS VULNERÁVEIS
-- Senhas fracas, informações sensíveis expostas
INSERT INTO users (username, email, password, password_hash, role, status, secret_token, api_key, credit_card, ssn, salary, notes, internal_id, debug_info, admin_notes) VALUES

-- Admin com senha fraca
('admin', 'admin@cyberlab.com', 'admin123', '$2b$10$rZ8Q8Q8Q8Q8Q8Q8Q8Q8Q8O', 'admin', 'active', 
 'secret_admin_token_123', 'api_key_admin_xyz789', '4532-1234-5678-9012', '123-45-6789', 150000.00,
 'Admin user with full privileges', 'ADM_001', 'Debug mode enabled for admin', 'Has access to all sensitive data'),

-- Usuário regular com informações vazadas
('user1', 'user1@email.com', 'password123', NULL, 'user', 'active',
 'user_token_weak_456', 'api_user1_abc123', '4111-1111-1111-1111', '987-65-4321', 45000.00,
 'Regular user account', 'USR_001', 'Standard debug info', 'Standard user permissions'),

-- Usuário com XSS em notas
('hacker', 'hacker@evil.com', 'hack123', NULL, 'user', 'active',
 'hacker_token_789', 'api_hacker_def456', '5555-5555-5555-4444', '111-22-3333', 0.00,
 '<script>alert("XSS in database!")</script>Hacker notes', 'USR_002', 'Suspicious activity detected', 'Monitor this user'),

-- Usuário inativo com dados sensíveis
('inactive_user', 'inactive@test.com', 'inactive123', '$2b$10$weak.hash.example', 'user', 'inactive',
 'inactive_token_000', 'api_inactive_ghi789', '3782-8224-6310-005', '555-66-7777', 75000.00,
 'Inactive user with sensitive data still accessible', 'USR_003', 'Account deactivated but data remains', 'Contains sensitive financial info'),

-- Moderador com privilégios elevados
('moderator', 'mod@cyberlab.com', 'mod123', '$2b$10$mod.weak.hash.example', 'moderator', 'active',
 'mod_secret_token_999', 'api_mod_jkl012', '6011-1111-1111-1117', '888-99-0000', 80000.00,
 'Moderator with elevated privileges', 'MOD_001', 'Moderator debug access enabled', 'Can modify user data'),

-- Usuário de teste com SQL injection em notas
('testuser', 'test@cyberlab.com', 'test123', NULL, 'user', 'active',
 'test_token_sql', 'api_test_sql123', '4000-0000-0000-0002', '222-33-4444', 30000.00,
 "'; DROP TABLE users; --", 'USR_004', 'SQL injection test data', 'Contains malicious SQL in notes field');

-- 🚨 INSERIR CONFIGURAÇÕES DO SISTEMA (sensíveis)
INSERT INTO system_config (config_key, config_value, is_sensitive, description) VALUES
('database_password', 'weak123', TRUE, 'Database connection password - EXPOSED!'),
('jwt_secret', 'super_secret_key_123', TRUE, 'JWT signing secret - WEAK!'),
('api_master_key', 'master_api_key_xyz789', TRUE, 'Master API key for admin access'),
('encryption_key', 'weak_encryption_key_456', TRUE, 'Key for encrypting sensitive data'),
('admin_email', 'admin@cyberlab.com', FALSE, 'Administrator email address'),
('debug_mode', 'enabled', FALSE, 'Debug mode status'),
('allow_file_upload', 'true', FALSE, 'File upload permission'),
('max_file_size', '50000000', FALSE, 'Maximum file upload size in bytes'),
('allowed_file_types', 'jpg,png,gif,pdf,txt,php,js,html', FALSE, 'Allowed file extensions - DANGEROUS!'),
('backup_location', '/var/backups/cyberlab', FALSE, 'Database backup location'),
('log_sensitive_data', 'true', FALSE, 'Whether to log sensitive information'),
('rate_limiting_disabled', 'true', FALSE, 'Rate limiting status - DISABLED!'),
('cors_origin', '*', FALSE, 'CORS allowed origins - WILDCARD!'),
('session_timeout', '86400000', FALSE, 'Session timeout in milliseconds - 24 hours!');

-- 🚨 INSERIR POSTS COM XSS
INSERT INTO posts (user_id, title, content, html_content, raw_input, sanitized_content) VALUES
(1, 'Welcome to CyberLab', 'Welcome to our vulnerable application!', 
 '<h1>Welcome to CyberLab</h1><p>This is a <strong>vulnerable</strong> application.</p>',
 'Welcome to our vulnerable application!', 'Welcome to our vulnerable application!'),

(3, 'XSS Test Post', 'This post contains XSS for testing', 
 '<script>alert("XSS Attack!")</script><p>Malicious content</p>',
 '<script>alert("XSS Attack!")</script>This post contains XSS', 
 'This post contains XSS for testing'), -- "Sanitized" but script remains!

(2, 'SQL Injection Example', 'This shows SQL injection in posts',
 '<p>Example: \' OR \'1\'=\'1\' --</p>',
 '\' OR \'1\'=\'1\' -- This shows SQL injection',
 'This shows SQL injection in posts'),

(1, 'File Upload Vulnerabilities', 'Information about file upload security',
 '<p>File uploads can be dangerous if not properly validated.</p><iframe src="javascript:alert(\'XSS via iframe\')"></iframe>',
 'File uploads info with <iframe src="javascript:alert(\'XSS via iframe\')"></iframe>',
 'File uploads can be dangerous if not properly validated.');

-- 🚨 INSERIR SESSÕES VULNERÁVEIS
INSERT INTO sessions (session_id, user_id, data, ip_address, user_agent, expires_at, is_admin) VALUES
('session_123456789', 1, '{"user_id":1,"role":"admin","permissions":["all"],"secret_data":"admin_secret_xyz"}', 
 '192.168.1.100', 'Mozilla/5.0 (Vulnerable Browser)', DATE_ADD(NOW(), INTERVAL 7 DAY), TRUE),

('predictable_session_001', 2, '{"user_id":2,"role":"user","last_action":"login"}',
 '10.0.0.5', 'Chrome/90.0 (Test User)', DATE_ADD(NOW(), INTERVAL 1 DAY), FALSE),

('weak_session_abc', 3, '{"user_id":3,"role":"user","notes":"hacker account","ip_history":["evil.com"]}',
 '172.16.0.10', 'Hacker Browser v1.0', DATE_ADD(NOW(), INTERVAL 12 HOUR), FALSE);

-- 🚨 INSERIR FILE UPLOADS VULNERÁVEIS
INSERT INTO file_uploads (user_id, original_filename, stored_filename, file_path, file_size, mime_type, file_hash, is_public, upload_ip, exif_data, virus_scan_result) VALUES
(1, 'profile.jpg', 'upload_1.jpg', '/uploads/profile/upload_1.jpg', 245760, 'image/jpeg', 'abc123hash', TRUE, '192.168.1.100', '{"camera":"iPhone","location":"37.7749,-122.4194"}', 'not_scanned'),

(3, 'shell.php', 'upload_2.php', '/uploads/files/upload_2.php', 1024, 'application/x-php', 'malicious_hash_456', TRUE, '172.16.0.10', NULL, 'not_scanned'),

(2, '../../../etc/passwd', 'upload_3.txt', '/uploads/../../../etc/passwd', 2048, 'text/plain', 'traversal_hash_789', TRUE, '10.0.0.5', NULL, 'infected'),

(1, 'document.pdf', 'upload_4.pdf', '/uploads/docs/upload_4.pdf', 512000, 'application/pdf', 'pdf_hash_012', FALSE, '192.168.1.100', '{"creator":"Vulnerable Creator","location":"Secret Location"}', 'clean');

-- 🚨 INSERIR PRODUTOS COM INFORMAÇÕES SENSÍVEIS
INSERT INTO products (name, description, price, stock, category_id, cost_price, supplier_info, profit_margin, internal_notes) VALUES
('Laptop', 'High-performance laptop for professionals', 999.99, 50, 1, 
 600.00, 'Supplier: TechCorp, Contact: secret@techcorp.com, Discount: 30%', 66.67, 
 'High profit margin item. Push this product. Supplier gives us kickbacks.'),

('Smartphone', 'Latest model smartphone with advanced features', 699.99, 100, 1,
 350.00, 'Supplier: PhoneMaker Inc, Emergency contact: +1-555-SECRET', 100.00,
 'Defective batch #12345 still in inventory. Do not sell units with serial starting with DEF.'),

('Headphones', 'Premium wireless headphones', 199.99, 75, 2,
 45.00, 'Supplier: AudioGear Ltd, CEO personal number: +1-555-0123', 344.42,
 'Customer returns due to battery issues. Reselling as new. Legal says it\'s OK.'),

('Monitor', '4K Ultra HD monitor for gaming', 399.99, 25, 1,
 180.00, 'Supplier: DisplayTech, Inside contact: John Doe (takes bribes)', 122.22,
 'Factory in China uses child labor. Marketing team aware but decided to ignore.');

-- 🚨 INSERIR PEDIDOS COM INFORMAÇÕES DE PAGAMENTO
INSERT INTO orders (user_id, total_amount, status, shipping_address, payment_method, card_last_four, transaction_id) VALUES
(2, 1199.98, 'delivered', '123 Main St, City, State 12345, USA', 'credit_card', '1111', 'TXN_ABC123456789'),
(1, 699.99, 'processing', '456 Admin Ave, Admin City, AC 54321, USA', 'credit_card', '9012', 'TXN_ADMIN_987654'),
(3, 199.99, 'cancelled', '789 Hacker Blvd, Dark Web, DW 00000, International', 'bitcoin', 'N/A', 'BTC_HACK_666'),
(2, 399.99, 'shipped', '321 User Lane, Normal Town, NT 98765, USA', 'debit_card', '4444', 'TXN_USER_555444');

-- 🚨 INSERIR DADOS CLASSIFICADOS PARA TESTES AVANÇADOS
INSERT INTO sensitive_data (data_type, classified_info, access_level, owner_id, json_data, xml_data, serialized_data) VALUES
('financial', 'Q4 revenue projections: $50M. Acquisition target: CompetitorCorp for $200M', 'confidential', 1,
 '{"revenue": 50000000, "target": "CompetitorCorp", "price": 200000000}',
 '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
 0x4F3A383A22737464436C617373223A303A7B7D), -- Serialized PHP object

('personal', 'Employee personal data: SSN, addresses, medical records', 'restricted', 1,
 '{"employees": [{"ssn": "123-45-6789", "medical": "diabetes"}]}',
 '<employees><employee ssn="123-45-6789" medical="diabetes"/></employees>',
 NULL),

('technical', 'Database credentials and API keys', 'top_secret', 1,
 '{"db_password": "weak123", "api_keys": ["secret123", "master456"]}',
 '<credentials><database password="weak123"/><api key="secret123"/></credentials>',
 NULL),

('intelligence', 'Competitor analysis and insider information', 'confidential', 1,
 '{"competitor_weaknesses": "poor security", "insider": "john@competitor.com"}',
 '<intelligence source="insider">Poor security at competitor</intelligence>',
 0x613A323A7B733A31303A22636F6D70657469746F72223B733A31323A22706F6F7220736563757269747922}); -- Another serialized object

-- 🚨 INSERIR LOGS DE SEGURANÇA VULNERÁVEIS
INSERT INTO security_logs (event_type, user_id, ip_address, user_agent, request_data, response_data, sql_query, payload, success, session_data, cookies, headers) VALUES
('LOGIN_ATTEMPT', 1, '192.168.1.100', 'Mozilla/5.0', 
 '{"username":"admin","password":"admin123","remember_me":true}',
 '{"success":true,"token":"jwt_admin_token_123","role":"admin"}',
 'SELECT * FROM users WHERE username = \'admin\' AND password = \'admin123\'',
 NULL, TRUE,
 '{"session_id":"session_123456789","user_id":1,"role":"admin"}',
 'session_id=session_123456789; auth_token=jwt_admin_token_123',
 '{"Authorization":"Bearer jwt_admin_token_123","User-Agent":"Mozilla/5.0"}'),

('SQL_INJECTION', 3, '172.16.0.10', 'Hacker Browser v1.0',
 '{"user_id":"1\' OR \'1\'=\'1","action":"get_user"}',
 '{"error":"SQL syntax error","users_exposed":true}',
 'SELECT * FROM users WHERE id = \'1\' OR \'1\'=\'1\'',
 '\' OR \'1\'=\'1', TRUE,
 '{"session_id":"weak_session_abc","attack_successful":true}',
 'PHPSESSID=weak_session_abc',
 '{"X-Forwarded-For":"172.16.0.10","X-Attack-Type":"SQLInjection"}'),

('XSS_ATTEMPT', 2, '10.0.0.5', 'Chrome/90.0',
 '{"comment":"<script>alert(\'XSS\')</script>","post_id":1}',
 '{"saved":true,"content":"<script>alert(\'XSS\')</script>"}',
 'INSERT INTO posts (content) VALUES (\'<script>alert(\\\'XSS\\\')</script>\')',
 '<script>alert(\'XSS\')</script>', TRUE,
 '{"session_id":"predictable_session_001","xss_stored":true}',
 'comment_draft=<script>alert(\'XSS\')</script>',
 '{"Content-Type":"application/json","X-XSS-Protection":"0"}'),

('FILE_UPLOAD', 3, '172.16.0.10', 'Hacker Browser v1.0',
 '{"filename":"shell.php","size":1024,"type":"application/x-php"}',
 '{"uploaded":true,"path":"/uploads/files/upload_2.php","executable":true}',
 'INSERT INTO file_uploads (original_filename, stored_filename) VALUES (\'shell.php\', \'upload_2.php\')',
 'PHP webshell code', TRUE,
 '{"session_id":"weak_session_abc","file_uploaded":"shell.php"}',
 'upload_session=active; file_type=php',
 '{"Content-Type":"multipart/form-data","X-Filename":"shell.php"}');

-- Inserir estatísticas para dashboard
INSERT INTO security_logs (event_type, success, created_at) VALUES
('LOGIN_ATTEMPT', TRUE, DATE_SUB(NOW(), INTERVAL 1 HOUR)),
('LOGIN_ATTEMPT', FALSE, DATE_SUB(NOW(), INTERVAL 2 HOUR)),
('SQL_INJECTION', TRUE, DATE_SUB(NOW(), INTERVAL 3 HOUR)),
('XSS_ATTEMPT', TRUE, DATE_SUB(NOW(), INTERVAL 4 HOUR)),
('FILE_UPLOAD', TRUE, DATE_SUB(NOW(), INTERVAL 5 HOUR)),
('COMMAND_INJECTION', TRUE, DATE_SUB(NOW(), INTERVAL 6 HOUR));

-- Confirmar inserção dos dados
SELECT 'Mock vulnerable data inserted successfully' as status;
SELECT COUNT(*) as total_users FROM users;
SELECT COUNT(*) as total_posts FROM posts;
SELECT COUNT(*) as total_sessions FROM sessions;
SELECT COUNT(*) as total_configs FROM system_config;
SELECT COUNT(*) as total_logs FROM security_logs;