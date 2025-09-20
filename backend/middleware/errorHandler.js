/**
 * 🚨 ERROR HANDLER VULNERÁVEL
 * 
 * ⚠️ Este handler é INTENCIONALMENTE INSEGURO
 * 🎓 Expõe stack traces e informações sensíveis
 * 🚨 NÃO usar em produção!
 */

const logger = require('./logger');

// Error handler que VAZA informações - VULNERÁVEL
const vulnerableErrorHandler = (err, req, res, next) => {
  logger.error('🚨 Error occurred:', {
    error: err.message,
    stack: err.stack, // Stack trace completo
    url: req.originalUrl,
    method: req.method,
    headers: req.headers, // VAZA todos os headers
    body: req.body, // VAZA body da requisição
    params: req.params,
    query: req.query,
    ip: req.ip,
    user_agent: req.get('User-Agent'),
    cookies: req.cookies, // VAZA cookies
    session: req.session, // VAZA dados de sessão
    timestamp: new Date().toISOString()
  });
  
  // Resposta que expõe TUDO - MUITO PERIGOSO!
  res.status(err.status || 500).json({
    success: false,
    error: {
      message: err.message,
      stack: err.stack, // EXPÕE stack trace
      code: err.code,
      errno: err.errno,
      syscall: err.syscall,
      type: err.constructor.name
    },
    request_info: {
      url: req.originalUrl,
      method: req.method,
      headers: req.headers, // EXPÕE headers sensíveis
      body: req.body, // EXPÕE dados do body
      query: req.query,
      params: req.params,
      ip: req.ip,
      user_agent: req.get('User-Agent')
    },
    server_info: {
      node_version: process.version,
      platform: process.platform,
      arch: process.arch,
      uptime: process.uptime(),
      memory_usage: process.memoryUsage(),
      environment: process.env.NODE_ENV,
      timestamp: new Date().toISOString()
    },
    database_info: {
      // VAZA informações do banco - PERIGOSO!
      host: process.env.DB_HOST,
      port: process.env.DB_PORT,
      database: process.env.DB_NAME,
      user: process.env.DB_USER
    },
    vulnerable_note: '🚨 This error response is intentionally detailed for educational purposes'
  });
};

// Error handler "seguro" (mas ainda com problemas)
const insecureErrorHandler = (err, req, res, next) => {
  logger.error('Error occurred:', err.message);
  
  // Ainda vaza informações, mas menos
  res.status(err.status || 500).json({
    success: false,
    error: err.message,
    code: err.status || 500,
    timestamp: new Date().toISOString(),
    path: req.originalUrl, // VAZA caminho
    // Stack trace apenas em desenvolvimento - mas sempre está em "dev"
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
  });
};

// Handler que simula diferentes tipos de erros comuns
const simulateError = (type) => {
  const errors = {
    sql_error: () => {
      const err = new Error("ER_BAD_FIELD_ERROR: Unknown column 'secret_data' in 'field list'");
      err.code = 'ER_BAD_FIELD_ERROR';
      err.errno = 1054;
      err.sqlMessage = "Unknown column 'secret_data' in 'field list'";
      err.sqlState = '42S22';
      err.index = 0;
      err.sql = "SELECT id, username, password_hash, secret_data FROM users WHERE id = 1";
      return err;
    },
    
    auth_error: () => {
      const err = new Error('Authentication failed: Invalid JWT token signature');
      err.code = 'AUTH_FAILED';
      err.token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'; // Token parcial
      err.user_id = null;
      return err;
    },
    
    file_error: () => {
      const err = new Error('EACCES: permission denied, open \'/etc/passwd\'');
      err.code = 'EACCES';
      err.errno = -13;
      err.syscall = 'open';
      err.path = '/etc/passwd'; // VAZA tentativa de acesso
      return err;
    },
    
    validation_error: () => {
      const err = new Error('Validation failed: Password must contain admin_secret_key');
      err.code = 'VALIDATION_ERROR';
      err.field = 'password';
      err.value = 'user_entered_password'; // VAZA valor inserido
      err.expected = 'admin_secret_key'; // VAZA chave secreta!
      return err;
    }
  };
  
  return errors[type] ? errors[type]() : new Error('Unknown error type');
};

module.exports = {
  vulnerable: vulnerableErrorHandler,
  insecure: insecureErrorHandler,
  simulate: simulateError
};