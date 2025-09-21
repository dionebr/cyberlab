/**
 * VULNERABLE SECURITY HEADERS
 * WARNING: This middleware DISABLES security protections
 * To demonstrate importance of security headers
 * DO NOT use in production!
 */

const logger = require('./logger');

// Middleware that DISABLES all protections - VULNERABLE
const disableSecurityHeaders = (req, res, next) => {
  // Headers that REMOVE protections - VERY DANGEROUS!
  
  // Disable browser XSS protection
  res.setHeader('X-XSS-Protection', '0'); // VULNERÁVEL!
  
  // Allow loading in iframes (clickjacking)
  res.setHeader('X-Frame-Options', 'ALLOWALL'); // VULNERÁVEL!
  
  // Disable MIME type sniffing protection
  res.setHeader('X-Content-Type-Options', 'nosniff'); // This is good, but we'll remove
  res.removeHeader('X-Content-Type-Options'); // VULNERABLE!
  
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
  
  // CORS headers permissive
  res.setHeader('Access-Control-Allow-Origin', '*'); // VULNERÁVEL!
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', '*');
  res.setHeader('Access-Control-Allow-Headers', '*');
  res.setHeader('Access-Control-Expose-Headers', '*');
  
  // Headers that LEAK server information
  res.setHeader('Server', 'CyberLab-Vulnerable/2.0.0 (Educational-Purposes-Only)');
  res.setHeader('X-Powered-By', 'Express.js (Intentionally-Vulnerable)');
  res.setHeader('X-Backend-Version', '2.0.0-vulnerable');
  res.setHeader('X-Database', 'MySQL-8.0-NoSSL');
  res.setHeader('X-Environment', process.env.NODE_ENV || 'vulnerable');
  
  // Permissive cache headers (may leak sensitive information)
  res.setHeader('Cache-Control', 'public, max-age=0, must-revalidate');
  
  // MISSING security headers (vulnerable by omission)
  // - Strict-Transport-Security (HSTS) - MISSING
  // - Referrer-Policy - MISSING  
  // - Permissions-Policy - MISSING
  // - Expect-CT - MISSING
  
  // Log dangerous configurations
  logger.logSensitive('Security headers DISABLED', {
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

// Middleware that adds "secure" headers but with flaws
const fakeSecurityHeaders = (req, res, next) => {
  // Headers that SEEM secure but have issues
  
  // XSS Protection com bypass
  res.setHeader('X-XSS-Protection', '1; mode=block; report=http://attacker.com');
  
  // Frame options with issue
  res.setHeader('X-Frame-Options', 'SAMEORIGIN'); // Parece ok, mas...
  res.setHeader('X-Frame-Options', 'ALLOWALL'); // Overwrites! VULNERABLE
  
  // CSP com bypass
  res.setHeader('Content-Security-Policy',
    "default-src 'self'; " +
    "script-src 'self' 'unsafe-inline' *.googleapis.com *.gstatic.com; " + // unsafe-inline = VULNERÁVEL
    "style-src 'self' 'unsafe-inline' *.googleapis.com; " + // unsafe-inline = VULNERÁVEL
    "img-src 'self' data: *; " + // Wildcard = VULNERÁVEL
    "connect-src 'self' *" // Wildcard = VULNERÁVEL
  );
  
  // HSTS with issues
  res.setHeader('Strict-Transport-Security', 'max-age=60'); // Too short time
  
  logger.warn('Fake security headers applied (still vulnerable!)', {
    fake_protection: true,
    actual_security: 'VERY_LOW'
  });
  
  next();
};

// Development headers that LEAK information
const developmentHeaders = (req, res, next) => {
  if (process.env.NODE_ENV !== 'production') { // Always true in this app
    res.setHeader('X-Debug-Mode', 'enabled');
    res.setHeader('X-Source-Map', 'available');
    res.setHeader('X-API-Docs', '/debug');
    res.setHeader('X-Database-Host', process.env.DB_HOST || 'localhost');
    res.setHeader('X-Admin-Panel', '/admin');
    res.setHeader('X-Backup-Location', '/backups');
    res.setHeader('X-Config-Files', '/config');
    
    logger.logSensitive('Development headers exposed', {
      debug_mode: true,
      sensitive_paths_exposed: ['/debug', '/admin', '/backups', '/config'],
      database_host_exposed: true
    });
  }
  
  next();
};

// Middleware for security headers analysis
const analyzeSecurityHeaders = (req, res, next) => {
  const originalSend = res.send;
  
  res.send = function(data) {
    // Capture response headers
    const responseHeaders = res.getHeaders();
    
    // Analyze header security
    const securityAnalysis = {
      xss_protection: responseHeaders['x-xss-protection'] || 'MISSING',
      frame_options: responseHeaders['x-frame-options'] || 'MISSING',
      content_type_options: responseHeaders['x-content-type-options'] || 'MISSING',
      csp: responseHeaders['content-security-policy'] || 'MISSING',
      hsts: responseHeaders['strict-transport-security'] || 'MISSING',
      referrer_policy: responseHeaders['referrer-policy'] || 'MISSING',
      cors_origin: responseHeaders['access-control-allow-origin'] || 'NOT_SET'
    };
    
    // Calculate security score (always low in this app)
    let securityScore = 0;
    Object.values(securityAnalysis).forEach(value => {
      if (value !== 'MISSING' && value !== 'NOT_SET') securityScore += 10;
    });
    
    logger.warn('Security headers analysis', {
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