/**
 * VULNERABLE LOGGING MIDDLEWARE
 * WARNING: This logger is INTENTIONALLY INSECURE
 * DO NOT use in production!
 */

const winston = require('winston');
const fs = require('fs');
const path = require('path');

// Ensure log directory exists
const logDir = path.join(__dirname, '../logs');
if (!fs.existsSync(logDir)) {
  fs.mkdirSync(logDir, { recursive: true });
}

// VULNERABLE LOGGING CONFIGURATION
const logger = winston.createLogger({
  level: 'silly', // Log TUDO - incluindo dados sensíveis
  
  format: winston.format.combine(
    winston.format.timestamp(),
  winston.format.errors({ stack: true }),
    winston.format.printf(({ level, message, timestamp, stack, ...meta }) => {
  // VULNERABLE: Logs sensitive data without filtering
      const metaStr = Object.keys(meta).length ? JSON.stringify(meta, null, 2) : '';
      const stackStr = stack ? `\nStack: ${stack}` : '';
      return `[${timestamp}] ${level.toUpperCase()}: ${message}${stackStr}${metaStr ? `\nMeta: ${metaStr}` : ''}`;
    })
  ),
  
  transports: [
  // Console with colors (leaks sensitive info)
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      )
    }),
    
  // General log file - VULNERABLE: no rotation, unlimited growth
    new winston.transports.File({
      filename: path.join(logDir, 'cyberlab-all.log'),
      maxsize: null, // SEM limite de tamanho - DoS possível
      maxFiles: null, // SEM rotação de arquivos
      tailable: true
    }),
    
  // Error log file - also vulnerable
    new winston.transports.File({
      filename: path.join(logDir, 'cyberlab-errors.log'),
      level: 'error',
      maxsize: null,
      maxFiles: null
    }),
    
  // ATTACK log file - dangerous
    new winston.transports.File({
      filename: path.join(logDir, 'attacks.log'),
      level: 'warn'
    }),
    
  // SENSITIVE DATA log file - very dangerous
    new winston.transports.File({
      filename: path.join(logDir, 'sensitive-data.log'),
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.printf(({ timestamp, message, ...meta }) => {
          return `[${timestamp}] SENSITIVE: ${message} ${JSON.stringify(meta)}`;
        })
      )
    })
  ],
  
  // VULNERABLE: Does not handle exceptions properly
  exceptionHandlers: [
    new winston.transports.File({ 
      filename: path.join(logDir, 'exceptions.log'),
      maxsize: null
    })
  ],
  
  // VULNERABLE: Does not handle promise rejections
  rejectionHandlers: [
    new winston.transports.File({ 
      filename: path.join(logDir, 'rejections.log'),
      maxsize: null
    })
  ]
});

// VULNERABLE LOGGING FUNCTIONS

// Log sensitive data - VERY DANGEROUS!
logger.logSensitive = (message, data = {}) => {
  logger.info(`🔓 SENSITIVE DATA: ${message}`, {
    sensitive: true,
  data: data, // Includes passwords, tokens, etc.
    timestamp: new Date().toISOString(),
  caller: new Error().stack.split('\n')[2].trim()
  });
};

// Log attack attempts with full payload
logger.logAttack = (type, payload, userIP, userAgent) => {
  logger.warn(`🚨 ATTACK DETECTED: ${type}`, {
    attack_type: type,
  payload: payload, // Full payload - may be malicious
    source_ip: userIP,
    user_agent: userAgent,
    timestamp: new Date().toISOString(),
  successful: false // Will be updated if attack succeeds
  });
};

// Log successful attacks
logger.logAttackSuccess = (type, payload, result, userIP) => {
  logger.error(`💀 SUCCESSFUL ATTACK: ${type}`, {
    attack_type: type,
    payload: payload,
  result: result, // Attack result
    source_ip: userIP,
    timestamp: new Date().toISOString(),
    successful: true,
  severity: 'CRITICAL'
  });
};

// Log vulnerable SQL queries
const logVulnerableQuery = (query, parameters, ip, user) => {
  logger.warn('VULNERABLE_SQL_EXECUTED', {
  sql_query: query,
  parameters: parameters,
  client_ip: ip,
  user: user,
  timestamp: new Date(),
  severity: 'HIGH',
  category: 'SQL_INJECTION'
  });
  
  // Additional detailed log
  logger.error('SQL_INJECTION_ATTEMPT', {
  raw_query: query,
  params: parameters,
  ip: ip,
  user_context: user,
  stack: new Error().stack
  });
};

// VULNERABLE COMMAND LOGGING

// Log executed shell commands
const logVulnerableCommand = (command, parameters, ip, user) => {
  logger.warn('VULNERABLE_COMMAND_EXECUTED', {
  command: command,
  parameters: parameters,
  client_ip: ip,
  user: user,
  timestamp: new Date(),
  severity: 'HIGH',
  category: 'COMMAND_INJECTION'
  });
  
  // Additional detailed log
  logger.error('COMMAND_EXECUTION', {
  raw_command: command,
  params: parameters,
  ip: ip,
  user_context: user,
  stack: new Error().stack
  });
};

// Log dangerous file uploads
logger.logDangerousUpload = (filename, mimetype, size, path, userIP) => {
  logger.warn(`📁 DANGEROUS FILE UPLOADED`, {
    filename: filename,
    mimetype: mimetype,
    size: size,
  saved_path: path, // Full path - information disclosure
    source_ip: userIP,
    timestamp: new Date().toISOString(),
    risk_level: 'HIGH'
  });
};

// Log system command execution
logger.logCommandExecution = (command, output, exitCode, userIP) => {
  logger.error(`⚡ SYSTEM COMMAND EXECUTED`, {
  command: command, // Full command
  output: output, // Full output - may leak info
    exit_code: exitCode,
    source_ip: userIP,
    timestamp: new Date().toISOString(),
    severity: 'CRITICAL',
    system_info: {
      platform: process.platform,
      arch: process.arch,
      node_version: process.version
    }
  });
};

// Log authentication bypass
logger.logAuthBypass = (method, payload, userIP, result) => {
  logger.error(`🔓 AUTHENTICATION BYPASS ATTEMPT`, {
  bypass_method: method,
  payload: payload,
  source_ip: userIP,
  successful: result.success,
  user_compromised: result.user || null,
  timestamp: new Date().toISOString(),
  severity: result.success ? 'CRITICAL' : 'HIGH'
  });
};

// Function to read logs (VULNERABLE - exposes logs via API)
logger.readLogFile = (logType = 'all') => {
  const logFiles = {
    all: 'cyberlab-all.log',
    errors: 'cyberlab-errors.log', 
    attacks: 'attacks.log',
  sensitive: 'sensitive-data.log', // VERY DANGEROUS!
    exceptions: 'exceptions.log'
  };
  
  const filename = logFiles[logType] || logFiles.all;
  const filepath = path.join(logDir, filename);
  
  try {
    if (fs.existsSync(filepath)) {
      return fs.readFileSync(filepath, 'utf8');
    }
    return 'Log file not found';
  } catch (error) {
    logger.error('Failed to read log file:', error);
    return 'Error reading log file';
  }
};

// Function to clear logs (no authentication - VULNERABLE)
logger.clearLogs = (logType = 'all') => {
  const logFiles = {
    all: 'cyberlab-all.log',
    errors: 'cyberlab-errors.log',
    attacks: 'attacks.log', 
    sensitive: 'sensitive-data.log',
    exceptions: 'exceptions.log'
  };
  
  if (logType === 'all') {
  // Clear all logs
    Object.values(logFiles).forEach(filename => {
      const filepath = path.join(logDir, filename);
      try {
        if (fs.existsSync(filepath)) {
          fs.writeFileSync(filepath, '');
          logger.info(`Cleared log file: ${filename}`);
        }
      } catch (error) {
  logger.error(`Failed to clear log file ${filename}:`, error);
      }
    });
  } else {
    const filename = logFiles[logType];
    if (filename) {
      const filepath = path.join(logDir, filename);
      try {
        if (fs.existsSync(filepath)) {
          fs.writeFileSync(filepath, '');
      logger.info(`Cleared log file: ${filename}`);
        }
      } catch (error) {
  logger.error(`Failed to clear log file ${filename}:`, error);
      }
    }
  }
};

// Add initialization timestamp
logger.info('CyberLab Vulnerable Logger initialized', {
  log_level: 'silly',
  security_level: 'NONE',
  log_directory: logDir,
  warning: 'This logger is INTENTIONALLY INSECURE.'
});

module.exports = {
  logger,
  logSensitive: logger.logSensitive,
  logVulnerableQuery,
  logVulnerableCommand,
  logAuthBypass: logger.logAuthBypass,
  clearLogs: logger.clearLogs,
  vulnerableLogger: (req, res, next) => {
    // Simple debug log
    try {
      logger.info(`${req.method} ${req.url}`, {
        ip: req.ip,
        timestamp: new Date()
      });
    } catch (error) {
      console.warn('Logger error:', error.message);
    }
    next();
  }
};