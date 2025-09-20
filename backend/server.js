/**
 * 🚨 CYBERLAB PROFESSIONAL - BACKEND VULNERÁVEL
 * 
 * ⚠️  ATENÇÃO: Esta aplicação é INTENCIONALMENTE VULNERÁVEL
 * 🎓 Desenvolvida para educação em segurança cibernética
 * 🔒 Execute APENAS em ambiente isolado/containerizado
 * 📚 Para uso educacional e pesquisa em segurança
 * 
 * NÃO use em produção ou redes corporativas!
 */

const express = require('express');
const cors = require('cors');
const morgan = require('morgan');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

// Import custom middleware
const { logger, vulnerableLogger } = require('./middleware/logger');
const { vulnerableErrorHandler } = require('./middleware/errorHandler');
const { vulnerableHeaders } = require('./middleware/securityHeaders');

// Debug das importações
console.log('🔍 Debug: logger =', typeof logger);
console.log('🔍 Debug: vulnerableLogger =', typeof vulnerableLogger);
console.log('🔍 Debug: vulnerableErrorHandler =', typeof vulnerableErrorHandler);
console.log('🔍 Debug: vulnerableHeaders =', typeof vulnerableHeaders);

// Import database connection (VULNERÁVEL) - com fallback
let db = null;
try {
  db = require('./config/database');
  console.log('✅ Database connection loaded');
} catch (error) {
  console.warn('⚠️ Database connection failed, continuing without DB:', error.message);
}

const app = express();
const PORT = process.env.PORT || 5000;

// 🚨 CONFIGURAÇÕES INTENCIONALMENTE VULNERÁVEIS
// Para fins educacionais - NÃO usar em produção!

// ============================================
// 🔧 CONFIGURAÇÃO DE MIDDLEWARES VULNERÁVEIS
// ============================================

// CORS permissivo - MUITO PERIGOSO!
app.use(cors({
  origin: '*', // Permite qualquer origem!
  credentials: true, // Com credenciais!
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: ['*'], // Qualquer header!
  exposedHeaders: ['*'] // Expõe todos os headers!
}));

app.use(express.json({ limit: '50mb' })); // Limite muito alto!
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(cookieParser());

// Logging vulnerável
app.use(vulnerableLogger);

// Headers inseguros
app.use(vulnerableHeaders);

// Error handling que vaza informações
app.use(vulnerableErrorHandler);

// ============================================
// 🚨 ROTAS DE API VULNERÁVEIS
// ============================================

// Sistema de autenticação vulnerável
try {
  app.use('/api/auth', require('./api/auth'));
} catch (e) { console.warn('Auth routes not loaded:', e.message); }

// Endpoints vulneráveis para demonstração de SQL Injection
try {
  app.use('/api/vulnerable', require('./api/vulnerabilities'));
} catch (e) { console.warn('SQL routes not loaded:', e.message); }

// Endpoints vulneráveis para demonstração de XSS
try {
  app.use('/api/xss', require('./api/xss'));
} catch (e) { console.warn('XSS routes not loaded:', e.message); }

// Endpoints vulneráveis para demonstração de Command Injection
try {
  app.use('/api/cmd', require('./api/command-injection'));
} catch (e) { console.warn('Command injection routes not loaded:', e.message); }

// Endpoints vulneráveis para demonstração de File Upload
try {
  app.use('/api/upload', require('./api/file-upload'));
} catch (e) { console.warn('File upload routes not loaded:', e.message); }

// ============================================
// 🔧 ROTAS DE DEBUG E INFORMAÇÕES SENSÍVEIS
// ============================================

// Session management FRACO - VULNERÁVEL
app.use(session({
  secret: 'weak-secret-123', // Secret fraco e hardcoded - PERIGOSO!
  resave: true, // Sempre salva - ineficiente
  saveUninitialized: true, // Salva sessões vazias
  cookie: { 
    secure: false, // HTTP permitido - VULNERÁVEL
    httpOnly: false, // JS pode acessar - VULNERÁVEL para XSS
    maxAge: 24 * 60 * 60 * 1000 * 7 // 7 dias - muito longo
  },
  name: 'sessionid' // Nome previsível
}));

// Logging de requests (incluindo dados sensíveis)
app.use(morgan('combined', {
  stream: {
    write: (message) => {
      // Log TUDO incluindo senhas e tokens - VULNERÁVEL
      logger.info('HTTP Request:', message.trim());
    }
  }
}));

// Headers de segurança DESABILITADOS - VULNERÁVEL
app.use(securityHeaders.disable); // Nosso middleware que DESABILITA proteções

// Servir arquivos estáticos sem restrições
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use('/logs', express.static(path.join(__dirname, 'logs'))); // PERIGOSO!

// ============================================
// ROUTES VULNERÁVEIS
// ============================================

// Root endpoint com informações sensíveis
app.get('/', (req, res) => {
  res.json({
    message: '🚨 CyberLab Professional - Backend Vulnerável',
    version: '2.0.0',
    environment: process.env.NODE_ENV || 'development',
    database: {
      host: process.env.DB_HOST || 'localhost',
      port: process.env.DB_PORT || 3306,
      user: process.env.DB_USER || 'vulnerable_user' // Expondo credenciais!
    },
    warnings: [
      '⚠️ Esta aplicação é INTENCIONALMENTE VULNERÁVEL',
      '🚨 NÃO use em ambientes de produção',
      '🔒 Execute apenas em ambiente isolado',
      '📚 Para fins educacionais apenas'
    ],
    endpoints: {
      auth: '/api/auth/*',
      sql: '/api/sql/*', 
      xss: '/api/xss/*',
      command: '/api/cmd/*',
      file: '/api/file/*'
    }
  });
});

// Health check que vaza informações - VULNERÁVEL
app.get('/health', (req, res) => {
  res.json({
    status: 'vulnerable_by_design',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    memory: process.memoryUsage(), // Informações do sistema
    environment: process.env, // VAZA TODAS as variáveis de ambiente!
    database_status: 'connected_without_ssl'
  });
});

// Debug endpoint que expõe código fonte - VULNERÁVEL
app.get('/debug', (req, res) => {
  if (req.query.file) {
    const filePath = path.join(__dirname, req.query.file);
    try {
      const content = fs.readFileSync(filePath, 'utf8');
      res.json({ 
        file: req.query.file,
        content: content // VAZA código fonte!
      });
    } catch (error) {
      res.json({ 
        error: error.message,
        stack: error.stack // VAZA stack trace!
      });
    }
  } else {
    res.json({
      message: 'Debug endpoint - use ?file=path/to/file',
      example: '/debug?file=server.js',
      warning: '🚨 This endpoint is EXTREMELY vulnerable!'
    });
  }
});

// ============================================
// ROUTES DA API (VULNERÁVEIS)
// ============================================

app.use('/api/auth', authRoutes);
app.use('/api/sql', sqlRoutes);  
app.use('/api/xss', xssRoutes);
app.use('/api/cmd', commandRoutes);
app.use('/api/file', fileRoutes);

// ============================================
// ERROR HANDLING VULNERÁVEL
// ============================================

// 404 handler que vaza informações
app.use((req, res) => {
  res.status(404).json({
    error: 'Route not found',
    requested_url: req.originalUrl,
    method: req.method,
    headers: req.headers, // VAZA todos os headers!
    ip: req.ip,
    user_agent: req.get('User-Agent'),
    timestamp: new Date().toISOString()
  });
});

// Global error handler que vaza stack traces
app.use(errorHandler.vulnerable);

// ============================================
// SERVER STARTUP
// ============================================

// Verificar conexão com database (sem SSL)
db.testConnection()
  .then(() => {
    logger.info('💀 Database connected (WITHOUT SSL) - VULNERABLE!');
    
    // Inicializar dados vulneráveis
    db.initVulnerableData()
      .then(() => {
        logger.info('🚨 Vulnerable data initialized successfully');
      })
      .catch(err => {
        logger.error('Failed to initialize vulnerable data:', err);
      });
  })
  .catch(err => {
    logger.error('Database connection failed:', err);
    logger.warn('🚨 Starting server without database - some features may not work');
  });

// Start server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`
╔═══════════════════════════════════════════════════════╗
║                                                       ║
║  🚨 CYBERLAB PROFESSIONAL - VULNERABLE BACKEND 🚨    ║
║                                                       ║
║  ⚠️  WARNING: INTENTIONALLY VULNERABLE APPLICATION   ║
║  🎓 For cybersecurity education purposes only        ║
║  🔒 Run ONLY in isolated/containerized environment   ║
║                                                       ║
║  🌐 Server running on: http://localhost:${PORT}        ║
║  📚 Documentation: /CYBERLAB-PROFESSIONAL-ROADMAP.md ║
║                                                       ║
║  🚨 DO NOT USE IN PRODUCTION ENVIRONMENTS! 🚨        ║
║                                                       ║
╚═══════════════════════════════════════════════════════╝
  `);
  
  logger.info(`🚨 CyberLab Vulnerable Backend started on port ${PORT}`);
  logger.warn('⚠️ This server is INTENTIONALLY VULNERABLE - Educational use only!');
});

// Graceful shutdown
process.on('SIGINT', () => {
  logger.info('🛑 Shutting down CyberLab Vulnerable Backend...');
  db.close();
  process.exit(0);
});

process.on('SIGTERM', () => {
  logger.info('🛑 Received SIGTERM, shutting down gracefully...');
  db.close();
  process.exit(0);
});

module.exports = app;