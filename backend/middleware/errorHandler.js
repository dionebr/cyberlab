/**
 * VULNERABLE ERROR HANDLER
 * WARNING: This handler is INTENTIONALLY INSECURE
 * Exposes stack traces and sensitive information
 * DO NOT use in production!
 */

const logger = require('./logger');

// Error handler that LEAKS information - VULNERABLE
const vulnerableErrorHandler = (err, req, res, next) => {
  logger.error('Error occurred:', {
    error: err.message,
    stack: err.stack, // Full stack trace
    url: req.originalUrl,
    method: req.method,
    headers: req.headers, // Leaks all headers
    body: req.body, // Leaks request body
    params: req.params,
    query: req.query,
    ip: req.ip,
    user_agent: req.get('User-Agent'),
    cookies: req.cookies, // Leaks cookies
    session: req.session, // Leaks session data
    timestamp: new Date().toISOString()
  });
  
  // Response that exposes EVERYTHING - VERY DANGEROUS!
  res.status(err.status || 500).json({
    success: false,
    error: {
      message: err.message,
      stack: err.stack, // EXPOSES stack trace
      code: err.code,
      errno: err.errno,
      syscall: err.syscall,
      type: err.constructor.name
    },
    request_info: {
      url: req.originalUrl,
      method: req.method,
      headers: req.headers, // EXPOSES sensitive headers
      body: req.body, // EXPOSES body data
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
      // Leaks database info - DANGEROUS!
      host: process.env.DB_HOST,
      port: process.env.DB_PORT,
      database: process.env.DB_NAME,
      user: process.env.DB_USER
    },
    vulnerable_note: 'This error response is intentionally detailed for educational purposes'
  });
};

// "Secure" error handler (but still has issues)
const insecureErrorHandler = (err, req, res, next) => {
  logger.error('Error occurred:', err.message);
  
  // Still leaks information, but less
  res.status(err.status || 500).json({
    success: false,
    error: err.message,
    code: err.status || 500,
    timestamp: new Date().toISOString(),
    path: req.originalUrl, // Leaks path
    // Stack trace only in development - but always in "dev"
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
  });
};

// Handler that simulates different types of common errors
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
      err.token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'; // Partial token
      err.user_id = null;
      return err;
    },
    
    file_error: () => {
      const err = new Error('EACCES: permission denied, open \'/etc/passwd\'');
      err.code = 'EACCES';
      err.errno = -13;
      err.syscall = 'open';
      err.path = '/etc/passwd'; // Leaks access attempt
      return err;
    },
    
    validation_error: () => {
      const err = new Error('Validation failed: Password must contain admin_secret_key');
      err.code = 'VALIDATION_ERROR';
      err.field = 'password';
      err.value = 'user_entered_password'; // Leaks entered value
      err.expected = 'admin_secret_key'; // Leaks secret key!
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