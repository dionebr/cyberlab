/**
 * CYBERLAB PROFESSIONAL - VULNERABLE BACKEND
 * WARNING: This application is INTENTIONALLY VULNERABLE
 * Run ONLY in isolated/containerized environments
 * DO NOT use in production!
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
const { vulnerable: vulnerableErrorHandler } = require('./middleware/errorHandler');
const { disable: vulnerableHeaders } = require('./middleware/securityHeaders');

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

// INTENTIONALLY VULNERABLE CONFIGURATION
// DO NOT use in production!

// ============================================
// VULNERABLE MIDDLEWARE CONFIGURATION
// ============================================

// Permissive CORS - VERY DANGEROUS!
app.use(cors({
  origin: '*', // Permite qualquer origem!
  credentials: true, // Com credenciais!
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: ['*'], // Qualquer header!
  exposedHeaders: ['*'] // Expõe todos os headers!
}));

app.use(express.json({ limit: '50mb' })); // Very high limit!
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(cookieParser());

// Logging vulnerável
app.use(vulnerableLogger);

// Insecure headers
app.use(vulnerableHeaders);

// Error handling that leaks information
app.use(vulnerableErrorHandler);

// ============================================
// VULNERABLE API ROUTES
// ============================================

// Vulnerable authentication system
try {
  app.use('/api/auth', require('./api/auth'));
} catch (e) { console.warn('Auth routes not loaded:', e.message); }

// Vulnerable endpoints for SQL Injection demonstration
try {
  app.use('/api/vulnerable', require('./api/vulnerabilities'));
} catch (e) { console.warn('SQL routes not loaded:', e.message); }

// Vulnerable endpoints for XSS demonstration
try {
  app.use('/api/xss', require('./api/xss'));
} catch (e) { console.warn('XSS routes not loaded:', e.message); }

// Vulnerable endpoints for Command Injection demonstration
try {
  app.use('/api/cmd', require('./api/command-injection'));
} catch (e) { console.warn('Command injection routes not loaded:', e.message); }

// Vulnerable endpoints for File Upload demonstration
try {
  app.use('/api/upload', require('./api/file-upload'));
} catch (e) { console.warn('File upload routes not loaded:', e.message); }

// ============================================
// DEBUG ROUTES AND SENSITIVE INFORMATION
// ============================================

// WEAK session management - VULNERABLE
app.use(session({
  secret: 'weak-secret-123', // Weak and hardcoded secret - DANGEROUS!
  resave: true, // Always saves - inefficient
  saveUninitialized: true, // Saves empty sessions
  cookie: { 
    secure: false, // HTTP allowed - VULNERABLE
    httpOnly: false, // JS can access - VULNERABLE to XSS
    maxAge: 24 * 60 * 60 * 1000 * 7 // 7 days - too long
  },
  name: 'sessionid' // Predictable name
}));

// Request logging (including sensitive data)
app.use(morgan('combined', {
  stream: {
    write: (message) => {
  // Log EVERYTHING including passwords and tokens - VULNERABLE
      logger.info('HTTP Request:', message.trim());
    }
  }
}));

// Security headers DISABLED - VULNERABLE
app.use(vulnerableHeaders); // Nosso middleware que DESABILITA proteções

// Serve static files without restrictions
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use('/logs', express.static(path.join(__dirname, 'logs'))); // DANGEROUS!

// ============================================
// VULNERABLE ROUTES
// ============================================

// Root endpoint with sensitive information
app.get('/', (req, res) => {
  res.json({
  message: 'CyberLab Professional - Vulnerable Backend',
    version: '2.0.0',
    environment: process.env.NODE_ENV || 'development',
    database: {
      host: process.env.DB_HOST || 'localhost',
      port: process.env.DB_PORT || 3306,
      user: process.env.DB_USER || 'vulnerable_user' // Exposing credentials!
    },
    warnings: [
      'WARNING: This application is INTENTIONALLY VULNERABLE',
      'DO NOT use in production environments',
      'Run only in isolated environments'
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

// Health check that leaks information - VULNERABLE
app.get('/health', (req, res) => {
  res.json({
    status: 'vulnerable_by_design',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
  memory: process.memoryUsage(), // System info
  environment: process.env, // Leaks ALL environment variables!
    database_status: 'connected_without_ssl'
  });
});

// Debug endpoint that exposes source code - VULNERABLE
app.get('/debug', (req, res) => {
  if (req.query.file) {
    const filePath = path.join(__dirname, req.query.file);
    try {
      const content = fs.readFileSync(filePath, 'utf8');
      res.json({ 
        file: req.query.file,
  content: content // Leaks source code!
      });
    } catch (error) {
      res.json({ 
        error: error.message,
  stack: error.stack // Leaks stack trace!
      });
    }
  } else {
    res.json({
      message: 'Debug endpoint - use ?file=path/to/file',
      example: '/debug?file=server.js',
  warning: 'This endpoint is EXTREMELY vulnerable!'
    });
  }
});

// ============================================
// VULNERABLE ERROR HANDLING
// ============================================

// 404 handler that leaks information
app.use((req, res) => {
  res.status(404).json({
    error: 'Route not found',
    requested_url: req.originalUrl,
    method: req.method,
  headers: req.headers, // Leaks all headers!
    ip: req.ip,
    user_agent: req.get('User-Agent'),
    timestamp: new Date().toISOString()
  });
});

// Global error handler that leaks stack traces
app.use(vulnerableErrorHandler);

// ============================================
// SERVER STARTUP
// ============================================

// Handlers to avoid crashes
process.on('uncaughtException', (error) => {
  logger.error('Uncaught Exception:', error);
  // Do NOT exit here to keep server running
});

process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
  // Do NOT exit here to keep server running
});

// Check database connection (no SSL)
db.testConnection()
  .then(() => {
    logger.info('Database connected (WITHOUT SSL) - VULNERABLE!');
    db.initVulnerableData()
      .then(() => {
        logger.info('Vulnerable data initialized successfully');
      })
      .catch(err => {
        logger.error('Failed to initialize vulnerable data:', err);
        // Continue even if initialization fails
      });
  })
  .catch(err => {
    logger.error('Database connection failed:', err);
  logger.warn('Starting server without database - some features may not work');
  });

// Start server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`
CYBERLAB PROFESSIONAL - VULNERABLE BACKEND
WARNING: INTENTIONALLY VULNERABLE APPLICATION
Run ONLY in isolated/containerized environment
Server running on: http://localhost:${PORT}
DO NOT USE IN PRODUCTION ENVIRONMENTS!
`);
  logger.info(`CyberLab Vulnerable Backend started on port ${PORT}`);
  logger.warn('This server is INTENTIONALLY VULNERABLE.');
});

// Graceful shutdown
process.on('SIGINT', () => {
  logger.info('Shutting down CyberLab Vulnerable Backend...');
  if (db && db.close) {
    db.close();
  }
  process.exit(0);
});

process.on('SIGTERM', () => {
  logger.info('Received SIGTERM, shutting down gracefully...');
  if (db && db.close) {
    db.close();
  }
  process.exit(0);
});

module.exports = app;