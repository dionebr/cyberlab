/**
 * 🚨 MIDDLEWARE DE LOGGING VULNERÁVEL
 * 
 * ⚠️ Este logger é INTENCIONALMENTE INSEGURO
 * 🎓 Para demonstrar problemas de logging em segurança
 * 🚨 NÃO usar em produção!
 */

const winston = require('winston');
const fs = require('fs');
const path = require('path');

// Garantir que o diretório de logs existe
const logDir = path.join(__dirname, '../logs');
if (!fs.existsSync(logDir)) {
  fs.mkdirSync(logDir, { recursive: true });
}

// 🚨 CONFIGURAÇÃO VULNERÁVEL DE LOGGING
const logger = winston.createLogger({
  level: 'silly', // Log TUDO - incluindo dados sensíveis
  
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }), // Stack traces completos
    winston.format.printf(({ level, message, timestamp, stack, ...meta }) => {
      // VULNERÁVEL: Log dados sensíveis sem filtro
      const metaStr = Object.keys(meta).length ? JSON.stringify(meta, null, 2) : '';
      const stackStr = stack ? `\nStack: ${stack}` : '';
      return `[${timestamp}] ${level.toUpperCase()}: ${message}${stackStr}${metaStr ? `\nMeta: ${metaStr}` : ''}`;
    })
  ),
  
  transports: [
    // Console com cores (vaza informações sensíveis)
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      )
    }),
    
    // Arquivo geral - VULNERÁVEL: sem rotação, crescimento ilimitado
    new winston.transports.File({
      filename: path.join(logDir, 'cyberlab-all.log'),
      maxsize: null, // SEM limite de tamanho - DoS possível
      maxFiles: null, // SEM rotação de arquivos
      tailable: true
    }),
    
    // Arquivo de erros - também vulnerável
    new winston.transports.File({
      filename: path.join(logDir, 'cyberlab-errors.log'),
      level: 'error',
      maxsize: null,
      maxFiles: null
    }),
    
    // 🚨 ARQUIVO EXTREMAMENTE PERIGOSO: logs de ataques
    new winston.transports.File({
      filename: path.join(logDir, 'attacks.log'),
      level: 'warn'
    }),
    
    // 🚨 ARQUIVO DE SENHAS E TOKENS (MUITO PERIGOSO!)
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
  
  // VULNERÁVEL: Não trata exceções adequadamente
  exceptionHandlers: [
    new winston.transports.File({ 
      filename: path.join(logDir, 'exceptions.log'),
      maxsize: null
    })
  ],
  
  // VULNERÁVEL: Não trata rejeições de promises
  rejectionHandlers: [
    new winston.transports.File({ 
      filename: path.join(logDir, 'rejections.log'),
      maxsize: null
    })
  ]
});

// 🚨 FUNÇÕES VULNERÁVEIS DE LOGGING

// Log senhas e dados sensíveis - MUITO PERIGOSO!
logger.logSensitive = (message, data = {}) => {
  logger.info(`🔓 SENSITIVE DATA: ${message}`, {
    sensitive: true,
    data: data, // Inclui senhas, tokens, etc.
    timestamp: new Date().toISOString(),
    caller: new Error().stack.split('\n')[2].trim()
  });
};

// Log tentativas de ataque com payload completo
logger.logAttack = (type, payload, userIP, userAgent) => {
  logger.warn(`🚨 ATTACK DETECTED: ${type}`, {
    attack_type: type,
    payload: payload, // Payload completo - pode ser malicioso
    source_ip: userIP,
    user_agent: userAgent,
    timestamp: new Date().toISOString(),
    successful: false // Será atualizado se o ataque funcionar
  });
};

// Log sucesso de ataques - para métricas educacionais
logger.logAttackSuccess = (type, payload, result, userIP) => {
  logger.error(`💀 SUCCESSFUL ATTACK: ${type}`, {
    attack_type: type,
    payload: payload,
    result: result, // Resultado do ataque
    source_ip: userIP,
    timestamp: new Date().toISOString(),
    successful: true,
    severity: 'CRITICAL'
  });
};

// Log queries SQL vulneráveis
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
  
  // Log adicional detalhado
  logger.error('SQL_INJECTION_ATTEMPT', {
    raw_query: query,
    params: parameters,
    ip: ip,
    user_context: user,
    stack: new Error().stack
  });
};

// ============================================
// 🚨 LOGGING ESPECÍFICO DE COMANDOS VULNERÁVEIS
// ============================================

// Log de comandos shell executados
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
  
  // Log adicional detalhado
  logger.error('COMMAND_EXECUTION', {
    raw_command: command,
    params: parameters,
    ip: ip,
    user_context: user,
    stack: new Error().stack
  });
};

// Log uploads de arquivos perigosos
logger.logDangerousUpload = (filename, mimetype, size, path, userIP) => {
  logger.warn(`📁 DANGEROUS FILE UPLOADED`, {
    filename: filename,
    mimetype: mimetype,
    size: size,
    saved_path: path, // Caminho completo - information disclosure
    source_ip: userIP,
    timestamp: new Date().toISOString(),
    risk_level: 'HIGH'
  });
};

// Log execução de comandos do sistema
logger.logCommandExecution = (command, output, exitCode, userIP) => {
  logger.error(`⚡ SYSTEM COMMAND EXECUTED`, {
    command: command, // Comando completo
    output: output, // Output completo - pode vazar informações
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

// Log bypass de autenticação
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

// Função para ler logs (VULNERÁVEL - expõe logs via API)
logger.readLogFile = (logType = 'all') => {
  const logFiles = {
    all: 'cyberlab-all.log',
    errors: 'cyberlab-errors.log', 
    attacks: 'attacks.log',
    sensitive: 'sensitive-data.log', // MUITO PERIGOSO!
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

// Função para limpar logs (sem autenticação - VULNERÁVEL)
logger.clearLogs = (logType = 'all') => {
  const logFiles = {
    all: 'cyberlab-all.log',
    errors: 'cyberlab-errors.log',
    attacks: 'attacks.log', 
    sensitive: 'sensitive-data.log',
    exceptions: 'exceptions.log'
  };
  
  if (logType === 'all') {
    // Limpar todos os logs
    Object.values(logFiles).forEach(filename => {
      const filepath = path.join(logDir, filename);
      try {
        if (fs.existsSync(filepath)) {
          fs.writeFileSync(filepath, '');
          logger.info(`🧹 Cleared log file: ${filename}`);
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
          logger.info(`🧹 Cleared log file: ${filename}`);
        }
      } catch (error) {
        logger.error(`Failed to clear log file ${filename}:`, error);
      }
    }
  }
};

// Adicionar timestamp de inicialização
logger.info('🚨 CyberLab Vulnerable Logger initialized', {
  log_level: 'silly',
  security_level: 'NONE',
  log_directory: logDir,
  warning: 'This logger is INTENTIONALLY INSECURE for educational purposes'
});

module.exports = {
  logger,
  logSensitive: logger.logSensitive,
  logVulnerableQuery,
  logVulnerableCommand,
  logAuthBypass: logger.logAuthBypass,
  clearLogs: logger.clearLogs,
  vulnerableLogger: (req, res, next) => {
    // Log TODAS as requisições com dados sensíveis
    logger.logSensitive('HTTP_REQUEST', {
      method: req.method,
      url: req.url,
      headers: req.headers, // Headers completos - pode conter tokens!
      body: req.body, // Body completo - pode conter senhas!
      query: req.query,
      params: req.params,
      cookies: req.cookies,
      ip: req.ip,
      user_agent: req.get('User-Agent'),
      referer: req.get('Referer'),
      session_id: req.sessionID,
      timestamp: new Date()
    });
    
    next();
  }
};