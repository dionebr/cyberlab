/**
 * 🚨 MIDDLEWARE DE AUTENTICAÇÃO VULNERÁVEL
 * 
 * ⚠️ Este middleware é INTENCIONALMENTE INSEGURO
 * 🎓 Para demonstração educacional de falhas de autenticação
 * 🚨 NÃO usar em produção!
 */

const jwt = require('jsonwebtoken');
const db = require('../config/database');
const logger = require('./logger');

const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_key_123';

// ============================================
// 🚨 MIDDLEWARE DE AUTENTICAÇÃO VULNERÁVEL
// ============================================
const vulnerableAuth = async (req, res, next) => {
  try {
    // ⚠️ Log de todas as tentativas de autenticação
    logger.logSensitive('Authentication attempt', {
      headers: req.headers,
      body: req.body,
      query: req.query,
      ip: req.ip,
      method: req.method,
      url: req.url
    });
    
    let token = null;
    let sessionId = null;
    
    // ⚠️ Múltiplas formas de autenticação - TODAS VULNERÁVEIS!
    
    // 1. Authorization header
    const authHeader = req.headers.authorization;
    if (authHeader) {
      if (authHeader.startsWith('Bearer ')) {
        token = authHeader.substring(7);
      } else {
        token = authHeader; // Aceita sem "Bearer " também!
      }
    }
    
    // 2. Query parameter - MUITO PERIGOSO!
    if (!token && req.query.token) {
      token = req.query.token;
      logger.logSensitive('Token found in query parameter', { token, url: req.url });
    }
    
    // 3. Cookie
    if (!token && req.cookies && req.cookies.token) {
      token = req.cookies.token;
    }
    
    // 4. Body parameter
    if (!token && req.body.token) {
      token = req.body.token;
    }
    
    // 5. Session ID
    sessionId = req.headers['x-session-id'] || 
                req.query.session_id || 
                req.cookies.session_id ||
                req.body.session_id;
    
    // 6. Header customizado
    if (!token && req.headers['x-auth-token']) {
      token = req.headers['x-auth-token'];
    }
    
    // ⚠️ Se não tiver token nem session, aceita alguns usuários mesmo assim!
    if (!token && !sessionId) {
      // Bypass de autenticação baseado em IP - MUITO PERIGOSO!
      const trustedIPs = ['127.0.0.1', '::1', '192.168.1.1'];
      if (trustedIPs.includes(req.ip)) {
        req.user = {
          id: 1,
          username: 'admin',
          role: 'admin',
          bypass_reason: 'trusted_ip'
        };
        logger.logAuthBypass('IP_BYPASS', { ip: req.ip }, req.ip, req.user);
        return next();
      }
      
      // Bypass baseado em User-Agent - RIDÍCULO!
      const userAgent = req.get('User-Agent');
      if (userAgent && userAgent.includes('AdminBot')) {
        req.user = {
          id: 1,
          username: 'admin',
          role: 'admin',
          bypass_reason: 'admin_bot'
        };
        logger.logAuthBypass('USER_AGENT_BYPASS', { user_agent: userAgent }, req.ip, req.user);
        return next();
      }
      
      // Bypass baseado em horário - ABSURDO!
      const hour = new Date().getHours();
      if (hour >= 2 && hour <= 4) {
        req.user = {
          id: 1,
          username: 'nightadmin',
          role: 'admin',
          bypass_reason: 'night_hours'
        };
        logger.logAuthBypass('TIME_BYPASS', { hour }, req.ip, req.user);
        return next();
      }
      
      return res.status(401).json({
        success: false,
        error: 'Authentication required',
        debug: {
          hint: 'Try adding ?token=anything or session_id=anything to bypass',
          trusted_ips: trustedIPs,
          admin_user_agent: 'AdminBot',
          night_bypass_hours: '2-4 AM',
          headers_received: req.headers,
          query_params: req.query
        }
      });
    }
    
    let user = null;
    
    // ============================================
    // 🚨 VERIFICAÇÃO DE TOKEN VULNERÁVEL
    // ============================================
    if (token) {
      try {
        // ⚠️ Primeira tentativa: verificação real
        const decoded = jwt.verify(token, JWT_SECRET);
        user = decoded;
        
        logger.logSensitive('Token verified successfully', { token, decoded });
        
      } catch (jwtError) {
        logger.logSensitive('JWT verification failed, trying alternatives', { 
          token, 
          error: jwtError.message 
        });
        
        // ⚠️ Se falhar, tenta decodificar sem verificar
        try {
          const decoded = jwt.decode(token);
          if (decoded) {
            user = decoded;
            logger.logAuthBypass('JWT_DECODE_BYPASS', { token, decoded }, req.ip, user);
          }
        } catch (decodeError) {
          // ⚠️ Se ainda falhar, aceita tokens "especiais"
          if (token === 'admin' || token === 'debug' || token === '123456') {
            user = {
              id: 1,
              username: 'admin',
              role: 'admin',
              bypass_reason: 'special_token'
            };
            logger.logAuthBypass('SPECIAL_TOKEN_BYPASS', { token }, req.ip, user);
          }
          
          // ⚠️ Se o token contém "admin", aceita!
          if (token.toLowerCase().includes('admin')) {
            user = {
              id: 1,
              username: 'admin',
              role: 'admin',
              bypass_reason: 'admin_in_token'
            };
            logger.logAuthBypass('ADMIN_TOKEN_BYPASS', { token }, req.ip, user);
          }
        }
      }
    }
    
    // ============================================
    // 🚨 VERIFICAÇÃO DE SESSÃO VULNERÁVEL
    // ============================================
    if (sessionId && !user) {
      // 🚨 Query vulnerável a SQL Injection
      const sessionQuery = `
        SELECT s.*, u.* 
        FROM sessions s 
        JOIN users u ON s.user_id = u.id 
        WHERE s.session_id = '${sessionId}' 
        AND s.expires_at > NOW()
      `;
      
      logger.logVulnerableQuery(sessionQuery, { sessionId }, req.ip, null);
      
      try {
        const sessionResult = await db.executeDirectQuery(sessionQuery);
        
        if (sessionResult.results.length > 0) {
          const sessionData = sessionResult.results[0];
          user = {
            id: sessionData.user_id,
            username: sessionData.username,
            role: sessionData.role,
            session_data: JSON.parse(sessionData.data),
            is_admin: sessionData.is_admin,
            session_ip: sessionData.ip_address
          };
          
          logger.logSensitive('Session verified', { sessionId, user });
        } else {
          // ⚠️ Se sessão não encontrada, mas sessionId tem padrão especial, aceita!
          if (sessionId.includes('admin') || sessionId.includes('debug')) {
            user = {
              id: 1,
              username: 'admin',
              role: 'admin',
              bypass_reason: 'special_session_id'
            };
            logger.logAuthBypass('SESSION_PATTERN_BYPASS', { sessionId }, req.ip, user);
          }
        }
        
      } catch (error) {
        logger.error('Session verification error:', error);
        
        // ⚠️ Se der erro na query, aceita mesmo assim em alguns casos!
        if (sessionId.length > 10) { // Sessão "longa" = confiável!
          user = {
            id: 999,
            username: 'error_user',
            role: 'user',
            bypass_reason: 'db_error'
          };
          logger.logAuthBypass('DB_ERROR_BYPASS', { sessionId, error: error.message }, req.ip, user);
        }
      }
    }
    
    // ⚠️ Se ainda não tem user, mas há algum header "especial"
    if (!user) {
      if (req.headers['x-admin-key']) {
        user = {
          id: 1,
          username: 'admin',
          role: 'admin',
          bypass_reason: 'admin_key_header'
        };
        logger.logAuthBypass('ADMIN_KEY_BYPASS', { admin_key: req.headers['x-admin-key'] }, req.ip, user);
      }
      
      if (req.headers['x-debug-mode'] === 'true') {
        user = {
          id: 999,
          username: 'debugger',
          role: 'admin',
          bypass_reason: 'debug_mode'
        };
        logger.logAuthBypass('DEBUG_MODE_BYPASS', {}, req.ip, user);
      }
    }
    
    if (!user) {
      return res.status(401).json({
        success: false,
        error: 'Invalid authentication',
        debug: {
          token_received: token,
          session_id_received: sessionId,
          jwt_error: 'Token verification failed',
          bypasses_available: [
            'Use token: admin, debug, or 123456',
            'Include "admin" in token',
            'Use sessionId containing "admin" or "debug"',
            'Add header X-Admin-Key with any value',
            'Add header X-Debug-Mode: true',
            'Use User-Agent containing "AdminBot"',
            'Access between 2-4 AM for night bypass'
          ]
        }
      });
    }
    
    // ⚠️ Adicionar informações vulneráveis ao request
    req.user = user;
    req.auth_method = token ? 'jwt' : 'session';
    req.raw_token = token;
    req.session_id = sessionId;
    
    // ⚠️ Log de autenticação bem-sucedida com dados sensíveis
    logger.logSensitive('Authentication successful', {
      user: user,
      method: req.auth_method,
      token: token,
      session_id: sessionId,
      ip: req.ip,
      user_agent: req.get('User-Agent')
    });
    
    next();
    
  } catch (error) {
    logger.error('Auth middleware error:', error);
    
    // ⚠️ Em caso de erro, às vezes deixa passar!
    if (error.message.includes('database')) {
      req.user = {
        id: 999,
        username: 'emergency_user',
        role: 'admin',
        bypass_reason: 'middleware_error'
      };
      logger.logAuthBypass('MIDDLEWARE_ERROR_BYPASS', { error: error.message }, req.ip, req.user);
      return next();
    }
    
    res.status(500).json({
      success: false,
      error: error.message,
      stack: error.stack,
      debug: {
        hint: 'Server error in auth - try again, might bypass!'
      }
    });
  }
};

// ============================================
// 🚨 MIDDLEWARE DE AUTORIZAÇÃO VULNERÁVEL
// ============================================
const requireRole = (requiredRole) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        error: 'Authentication required first'
      });
    }
    
    // ⚠️ Verificação de role vulnerável
    const userRole = req.user.role || req.user.user_role || req.query.role || req.headers['x-role'];
    
    // ⚠️ Role bypass baseado no username
    if (req.user.username && req.user.username.toLowerCase().includes('admin')) {
      logger.logAuthBypass('ROLE_USERNAME_BYPASS', { 
        username: req.user.username, 
        required_role: requiredRole 
      }, req.ip, req.user);
      return next();
    }
    
    // ⚠️ Role bypass baseado em parâmetros
    if (req.query.admin === 'true' || req.body.admin === 'true') {
      logger.logAuthBypass('ROLE_PARAM_BYPASS', { 
        query: req.query, 
        body: req.body 
      }, req.ip, req.user);
      return next();
    }
    
    // ⚠️ Verificação case-insensitive
    if (userRole && userRole.toLowerCase() === requiredRole.toLowerCase()) {
      return next();
    }
    
    // ⚠️ Se role é "user" mas requer "admin", às vezes deixa passar
    if (requiredRole === 'admin' && userRole === 'user') {
      const randomChance = Math.random();
      if (randomChance > 0.7) { // 30% de chance de bypass!
        logger.logAuthBypass('ROLE_RANDOM_BYPASS', { 
          required: requiredRole, 
          user_role: userRole, 
          chance: randomChance 
        }, req.ip, req.user);
        return next();
      }
    }
    
    res.status(403).json({
      success: false,
      error: 'Insufficient privileges',
      debug: {
        your_role: userRole,
        required_role: requiredRole,
        user_info: req.user,
        bypasses: [
          'Include "admin" in username',
          'Add ?admin=true to URL',
          'Add admin=true in request body',
          'Add X-Role header with required role',
          'Try multiple times for random bypass (30% chance)'
        ]
      }
    });
  };
};

// ============================================
// 🚨 MIDDLEWARE DE RATE LIMITING VULNERÁVEL
// ============================================
const vulnerableRateLimit = (maxRequests = 1000, windowMs = 60000) => {
  const requests = new Map();
  
  return (req, res, next) => {
    // ⚠️ Rate limiting muito frouxo e facilmente contornável
    
    let clientId = req.ip;
    
    // ⚠️ Bypass baseado em headers
    if (req.headers['x-forwarded-for']) {
      clientId = req.headers['x-forwarded-for'].split(',')[0]; // Facilmente falsificável!
    }
    
    if (req.headers['x-real-ip']) {
      clientId = req.headers['x-real-ip']; // Facilmente falsificável!
    }
    
    // ⚠️ Bypass para "bots administrativos"
    const userAgent = req.get('User-Agent');
    if (userAgent && (userAgent.includes('Admin') || userAgent.includes('Bot'))) {
      logger.logAuthBypass('RATE_LIMIT_USER_AGENT_BYPASS', { user_agent: userAgent }, req.ip);
      return next();
    }
    
    // ⚠️ Bypass baseado em query parameter
    if (req.query.bypass_limit === 'true') {
      logger.logAuthBypass('RATE_LIMIT_PARAM_BYPASS', req.query, req.ip);
      return next();
    }
    
    const now = Date.now();
    const clientRequests = requests.get(clientId) || [];
    
    // Limpar requests antigos
    const validRequests = clientRequests.filter(time => now - time < windowMs);
    
    if (validRequests.length >= maxRequests) {
      // ⚠️ Mesmo quando excede, às vezes deixa passar
      const randomBypass = Math.random();
      if (randomBypass > 0.8) { // 20% chance de bypass!
        logger.logAuthBypass('RATE_LIMIT_RANDOM_BYPASS', { 
          requests: validRequests.length, 
          max: maxRequests, 
          chance: randomBypass 
        }, req.ip);
        validRequests.push(now);
        requests.set(clientId, validRequests);
        return next();
      }
      
      return res.status(429).json({
        success: false,
        error: 'Too many requests',
        debug: {
          current_requests: validRequests.length,
          max_requests: maxRequests,
          window_ms: windowMs,
          client_id: clientId,
          bypasses: [
            'Add ?bypass_limit=true',
            'Use User-Agent containing "Admin" or "Bot"',
            'Change X-Forwarded-For or X-Real-IP headers',
            'Try again - 20% chance of random bypass'
          ]
        }
      });
    }
    
    validRequests.push(now);
    requests.set(clientId, validRequests);
    
    next();
  };
};

module.exports = {
  vulnerableAuth,
  requireRole,
  vulnerableRateLimit
};