/**
 * 🚨 SECURITY HEADERS VULNERÁVEIS
 * 
 * ⚠️ Este middleware DESABILITA proteções de segurança
 * 🎓 Para demonstrar importância dos security headers
 * 🚨 NÃO usar em produção!
 */

const logger = require('./logger');

// Middleware que DESABILITA todas as proteções - VULNERÁVEL
const disableSecurityHeaders = (req, res, next) => {
  // Headers que REMOVEM proteções - MUITO PERIGOSO!
  
  // Desabilitar proteção XSS do browser
  res.setHeader('X-XSS-Protection', '0'); // VULNERÁVEL!
  
  // Permitir carregamento em iframes (clickjacking)
  res.setHeader('X-Frame-Options', 'ALLOWALL'); // VULNERÁVEL!
  
  // Desabilitar proteção de MIME type sniffing
  res.setHeader('X-Content-Type-Options', 'nosniff'); // Esta é boa, mas vamos remover
  res.removeHeader('X-Content-Type-Options'); // VULNERÁVEL!
  
  // Content Security Policy PERMISSIVA - MUITO PERIGOSO!
  res.setHeader('Content-Security-Policy', 
    "default-src * 'unsafe-inline' 'unsafe-eval' data: blob:; " +
    "script-src * 'unsafe-inline' 'unsafe-eval'; " +
    "style-src * 'unsafe-inline'; " +
    "img-src * data: blob:; " +
    "font-src *; " +
    "connect-src *; " +
    "media-src *; " +
    "object-src *; " +
    "child-src *; " +
    "frame-src *; " +
    "worker-src *; " +
    "manifest-src *"
  );
  
  // CORS headers permissivos
  res.setHeader('Access-Control-Allow-Origin', '*'); // VULNERÁVEL!
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', '*');
  res.setHeader('Access-Control-Allow-Headers', '*');
  res.setHeader('Access-Control-Expose-Headers', '*');
  
  // Headers que VAZAM informações do servidor
  res.setHeader('Server', 'CyberLab-Vulnerable/2.0.0 (Educational-Purposes-Only)');
  res.setHeader('X-Powered-By', 'Express.js (Intentionally-Vulnerable)');
  res.setHeader('X-Backend-Version', '2.0.0-vulnerable');
  res.setHeader('X-Database', 'MySQL-8.0-NoSSL');
  res.setHeader('X-Environment', process.env.NODE_ENV || 'vulnerable');
  
  // Headers de cache permissivos (podem vazar informações sensíveis)
  res.setHeader('Cache-Control', 'public, max-age=0, must-revalidate');
  
  // Headers de segurança AUSENTES (vulneráveis por omissão)
  // - Strict-Transport-Security (HSTS) - AUSENTE
  // - Referrer-Policy - AUSENTE  
  // - Permissions-Policy - AUSENTE
  // - Expect-CT - AUSENTE
  
  // Log das configurações perigosas
  logger.logSensitive('🚨 Security headers DISABLED', {
    headers_disabled: [
      'X-XSS-Protection',
      'X-Frame-Options', 
      'X-Content-Type-Options',
      'Strict-Transport-Security',
      'Referrer-Policy'
    ],
    permissive_csp: true,
    cors_wildcard: true,
    server_info_exposed: true,
    risk_level: 'MAXIMUM'
  });
  
  next();
};

// Middleware que adiciona headers "seguros" mas com falhas
const fakeSecurityHeaders = (req, res, next) => {
  // Headers que PARECEM seguros mas têm problemas
  
  // XSS Protection com bypass
  res.setHeader('X-XSS-Protection', '1; mode=block; report=http://attacker.com');
  
  // Frame options com problema
  res.setHeader('X-Frame-Options', 'SAMEORIGIN'); // Parece ok, mas...
  res.setHeader('X-Frame-Options', 'ALLOWALL'); // Sobrescreve! VULNERÁVEL
  
  // CSP com bypass
  res.setHeader('Content-Security-Policy',
    "default-src 'self'; " +
    "script-src 'self' 'unsafe-inline' *.googleapis.com *.gstatic.com; " + // unsafe-inline = VULNERÁVEL
    "style-src 'self' 'unsafe-inline' *.googleapis.com; " + // unsafe-inline = VULNERÁVEL
    "img-src 'self' data: *; " + // Wildcard = VULNERÁVEL
    "connect-src 'self' *" // Wildcard = VULNERÁVEL
  );
  
  // HSTS com problemas
  res.setHeader('Strict-Transport-Security', 'max-age=60'); // Tempo muito curto
  
  logger.warn('🎭 Fake security headers applied (still vulnerable!)', {
    fake_protection: true,
    actual_security: 'VERY_LOW'
  });
  
  next();
};

// Headers de desenvolvimento que VAZAM informações
const developmentHeaders = (req, res, next) => {
  if (process.env.NODE_ENV !== 'production') { // Sempre true nesta app
    res.setHeader('X-Debug-Mode', 'enabled');
    res.setHeader('X-Source-Map', 'available');
    res.setHeader('X-API-Docs', '/debug');
    res.setHeader('X-Database-Host', process.env.DB_HOST || 'localhost');
    res.setHeader('X-Admin-Panel', '/admin');
    res.setHeader('X-Backup-Location', '/backups');
    res.setHeader('X-Config-Files', '/config');
    
    logger.logSensitive('🔧 Development headers exposed', {
      debug_mode: true,
      sensitive_paths_exposed: ['/debug', '/admin', '/backups', '/config'],
      database_host_exposed: true
    });
  }
  
  next();
};

// Middleware para análise de headers de segurança
const analyzeSecurityHeaders = (req, res, next) => {
  const originalSend = res.send;
  
  res.send = function(data) {
    // Capturar headers de resposta
    const responseHeaders = res.getHeaders();
    
    // Analisar segurança dos headers
    const securityAnalysis = {
      xss_protection: responseHeaders['x-xss-protection'] || 'MISSING',
      frame_options: responseHeaders['x-frame-options'] || 'MISSING',
      content_type_options: responseHeaders['x-content-type-options'] || 'MISSING',
      csp: responseHeaders['content-security-policy'] || 'MISSING',
      hsts: responseHeaders['strict-transport-security'] || 'MISSING',
      referrer_policy: responseHeaders['referrer-policy'] || 'MISSING',
      cors_origin: responseHeaders['access-control-allow-origin'] || 'NOT_SET'
    };
    
    // Calcular score de segurança (sempre baixo nesta app)
    let securityScore = 0;
    Object.values(securityAnalysis).forEach(value => {
      if (value !== 'MISSING' && value !== 'NOT_SET') securityScore += 10;
    });
    
    logger.warn('📊 Security headers analysis', {
      url: req.originalUrl,
      security_score: `${securityScore}/70`,
      headers_analysis: securityAnalysis,
      risk_assessment: securityScore < 40 ? 'HIGH_RISK' : 'MEDIUM_RISK'
    });
    
    return originalSend.call(this, data);
  };
  
  next();
};

module.exports = {
  disable: disableSecurityHeaders,
  fake: fakeSecurityHeaders, 
  development: developmentHeaders,
  analyze: analyzeSecurityHeaders
};