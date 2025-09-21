/**
 * VULNERABLE AUTHENTICATION SYSTEM
 * WARNING: This system is INTENTIONALLY INSECURE
 * For demonstration of authentication flaws
 * DO NOT use in production!
 */

const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const db = require('../config/database');
const logger = require('../middleware/logger');

// Simple UUID generator (CommonJS compatible)
function generateUUID() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    const r = Math.random() * 16 | 0;
    const v = c == 'x' ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
}

const router = express.Router();

// VULNERABLE CONFIGURATION
const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_key_123'; // Weak secret!
const JWT_EXPIRES_IN = '7d'; // Very long expiration - VULNERABLE!
const WEAK_BCRYPT_ROUNDS = 4; // Very low rounds - VULNERABLE!

// ============================================
// VULNERABLE REGISTRATION ENDPOINT
// ============================================
router.post('/register', async (req, res) => {
  try {
    const { username, email, password, role } = req.body;
    
  // Log sensitive data - VULNERABLE!
    logger.logSensitive('Registration attempt', { 
      username, 
      email, 
      password: password, // Logging plaintext password - VERY DANGEROUS!
      ip: req.ip 
    });
    
  // Weak validation - VULNERABLE!
    if (!username || !password) {
      return res.status(400).json({
        success: false,
        error: 'Username and password required',
        debug_info: {
          received_data: req.body, // Leaks received data!
          headers: req.headers,
          ip: req.ip
        }
      });
    }
    
  // Vulnerable SQL query - no prepared statements
    const checkUserQuery = `SELECT * FROM users WHERE username = '${username}' OR email = '${email}'`;
    const existingUser = await db.executeDirectQuery(checkUserQuery);
    
    if (existingUser.results.length > 0) {
      return res.status(409).json({
        success: false,
        error: 'User already exists',
  existing_user: existingUser.results[0], // Leaks existing user data!
  sql_query: checkUserQuery // Leaks SQL query!
      });
    }
    
  // Weak password hash - VULNERABLE!
    let passwordHash;
    if (password.length < 4) {
  // Very short passwords stored in plaintext - VERY DANGEROUS!
      passwordHash = password;
      logger.logSensitive('Password too short, stored in plaintext', { username, password });
    } else {
  // Hash with very low rounds - VULNERABLE!
      passwordHash = await bcrypt.hash(password, WEAK_BCRYPT_ROUNDS);
    }
    
  // Vulnerable insert query
  const userRole = role || 'user'; // No role validation - can become admin!
    const insertQuery = `
      INSERT INTO users 
      (username, email, password, password_hash, role, secret_token, api_key, created_at) 
      VALUES 
      ('${username}', '${email}', '${password}', '${passwordHash}', '${userRole}', 
       '${username}_token_${Date.now()}', 'api_${username}_${Math.random()}', NOW())
    `;
    
    const result = await db.executeDirectQuery(insertQuery);
    const userId = result.results.insertId;
    
  // Generate JWT with weak secret
    const token = jwt.sign(
      { 
        id: userId, 
        username: username, 
        role: userRole,
  password: password, // Password in JWT - VERY DANGEROUS!
        secret_token: `${username}_token_${Date.now()}`
      }, 
      JWT_SECRET, 
      { expiresIn: JWT_EXPIRES_IN }
    );
    
  // Session with predictable ID
    const sessionId = `${username}_session_${Date.now()}`;
    const sessionData = JSON.stringify({
      user_id: userId,
      username: username,
      role: userRole,
      login_time: new Date(),
      ip: req.ip,
      user_agent: req.get('User-Agent'),
  password: password // Password in session - DANGEROUS!
    });
    
  // Save session in database
    const sessionQuery = `
      INSERT INTO sessions (session_id, user_id, data, ip_address, user_agent, expires_at, is_admin)
      VALUES ('${sessionId}', ${userId}, '${sessionData}', '${req.ip}', '${req.get('User-Agent')}', 
              DATE_ADD(NOW(), INTERVAL 7 DAY), ${userRole === 'admin' ? 1 : 0})
    `;
    await db.executeDirectQuery(sessionQuery);
    
  // Response leaking sensitive information
    res.status(201).json({
      success: true,
      message: 'User registered successfully',
      user: {
        id: userId,
        username: username,
        email: email,
        role: userRole,
  password_hash: passwordHash, // Leaks password hash!
        secret_token: `${username}_token_${Date.now()}`
      },
      auth: {
        token: token,
        session_id: sessionId,
        expires_in: JWT_EXPIRES_IN
      },
      debug: {
  sql_query: insertQuery, // Leaks SQL query!
  bcrypt_rounds: WEAK_BCRYPT_ROUNDS,
  jwt_secret: JWT_SECRET, // Leaks JWT secret!
  raw_password: password // Leaks plaintext password!
      }
    });
    
    logger.logSensitive('User registered successfully', {
      user_id: userId,
      username: username,
      password: password,
      token: token,
      session_id: sessionId
    });
    
  } catch (error) {
    logger.error('Registration error:', error);
    
  // Error response leaking information
    res.status(500).json({
      success: false,
      error: error.message,
  stack: error.stack, // Leaks stack trace!
      sql_state: error.sqlState,
      sql_message: error.sqlMessage,
      errno: error.errno
    });
  }
});

// ============================================
// VULNERABLE LOGIN ENDPOINT
// ============================================
router.post('/login', async (req, res) => {
  try {
    const { username, password, remember_me } = req.body;
    
  // Log login attempt with password
    logger.logSensitive('Login attempt', { 
      username, 
      password: password, // Logging password!
      ip: req.ip,
      user_agent: req.get('User-Agent'),
      remember_me
    });
    
  // Vulnerable to SQL Injection
    const loginQuery = `
      SELECT id, username, email, password, password_hash, role, secret_token, api_key, salary, credit_card, ssn
      FROM users 
      WHERE username = '${username}' AND (password = '${password}' OR password_hash = '${password}')
    `;
    
  logger.logVulnerableQuery(loginQuery, { username, password }, req.ip, null);
    
    const userResult = await db.executeDirectQuery(loginQuery);
    
    if (userResult.results.length === 0) {
  // Response that facilitates user enumeration
      return res.status(401).json({
        success: false,
        error: 'Invalid credentials',
        debug: {
          query_executed: loginQuery, // Leaks query!
          users_found: userResult.results.length,
          attempted_username: username,
          attempted_password: password, // Leaks attempted password!
          hint: 'Try SQL injection: admin\' OR \'1\'=\'1\' --'
        }
      });
    }
    
    const user = userResult.results[0];
    
  // Weak password verification
    let passwordValid = false;
    
    if (user.password === password) {
  // Plaintext password - accepted directly
      passwordValid = true;
      logger.logSensitive('Password verified (plaintext)', { username, password });
    } else if (user.password_hash) {
  // Check hash
      try {
        passwordValid = await bcrypt.compare(password, user.password_hash);
        if (passwordValid) {
          logger.logSensitive('Password verified (hash)', { username, password, hash: user.password_hash });
        }
      } catch (error) {
  // If hash verification fails, accept anyway - VERY DANGEROUS!
        passwordValid = true;
        logger.logSensitive('Hash verification failed, accepting anyway', { username, error: error.message });
      }
    }
    
    if (!passwordValid) {
      return res.status(401).json({
        success: false,
        error: 'Invalid password',
        debug: {
          stored_password: user.password, // Leaks stored password!
          stored_hash: user.password_hash, // Leaks hash!
          attempted_password: password
        }
      });
    }
    
  // JWT with sensitive information
    const tokenPayload = {
      id: user.id,
      username: user.username,
      email: user.email,
      role: user.role,
  password: user.password, // Password in token!
      secret_token: user.secret_token,
      api_key: user.api_key,
      sensitive_data: {
        salary: user.salary,
        credit_card: user.credit_card,
        ssn: user.ssn
      },
      login_time: Date.now(),
      ip: req.ip
    };
    
    const token = jwt.sign(tokenPayload, JWT_SECRET, { 
      expiresIn: remember_me ? '30d' : JWT_EXPIRES_IN // 30 dias se lembrar!
    });
    
    // 🚨 Sessão com dados sensíveis
    const sessionId = `${username}_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    const sessionData = JSON.stringify({
      user_id: user.id,
      username: user.username,
      role: user.role,
      login_time: new Date(),
      ip: req.ip,
      user_agent: req.get('User-Agent'),
  full_user_data: user, // ALL user data in session!
      token: token
    });
    
  // Update or create session
    const sessionQuery = `
      INSERT INTO sessions (session_id, user_id, data, ip_address, user_agent, expires_at, is_admin)
      VALUES ('${sessionId}', ${user.id}, '${sessionData}', '${req.ip}', '${req.get('User-Agent')}', 
              DATE_ADD(NOW(), INTERVAL ${remember_me ? 30 : 7} DAY), ${user.role === 'admin' ? 1 : 0})
      ON DUPLICATE KEY UPDATE 
        data = '${sessionData}', 
        expires_at = DATE_ADD(NOW(), INTERVAL ${remember_me ? 30 : 7} DAY)
    `;
    await db.executeDirectQuery(sessionQuery);
    
  // Update last login
    const updateLoginQuery = `UPDATE users SET last_login = NOW() WHERE id = ${user.id}`;
    await db.executeDirectQuery(updateLoginQuery);
    
  // Log authentication success
    logger.logAuthBypass('LOGIN_SUCCESS', { username, password }, req.ip, {
      success: true,
      user: user,
      token: token,
      session_id: sessionId
    });
    
  // Response leaking ALL sensitive information
    res.json({
      success: true,
      message: 'Login successful',
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
  password: user.password, // Leaks password!
  password_hash: user.password_hash, // Leaks hash!
  secret_token: user.secret_token, // Leaks secret token!
  api_key: user.api_key, // Leaks API key!
  salary: user.salary, // Leaks salary!
  credit_card: user.credit_card, // Leaks credit card!
  ssn: user.ssn, // Leaks SSN!
        last_login: new Date()
      },
      auth: {
        token: token,
        session_id: sessionId,
        expires_in: remember_me ? '30d' : JWT_EXPIRES_IN,
  jwt_secret: JWT_SECRET // Leaks secret!
      },
      debug: {
  login_query: loginQuery, // Leaks query!
  password_verification: 'success',
  bcrypt_rounds_used: WEAK_BCRYPT_ROUNDS,
  session_data: sessionData // Leaks session data!
      },
      server_time: new Date().toISOString(),
      client_ip: req.ip
    });
    
  } catch (error) {
    logger.error('Login error:', error);
    
    res.status(500).json({
      success: false,
      error: error.message,
      stack: error.stack,
      sql_error: error.sqlMessage,
      errno: error.errno,
  debug_query: req.body // Leaks request data!
    });
  }
});

// ============================================
// VULNERABLE LOGOUT ENDPOINT
// ============================================
router.post('/logout', async (req, res) => {
  try {
    const { session_id, token } = req.body;
    
  // Log logout with sensitive information
    logger.logSensitive('Logout attempt', {
      session_id,
      token,
      ip: req.ip,
      headers: req.headers
    });
    
    if (session_id) {
  // Vulnerable query to fetch session
      const sessionQuery = `SELECT * FROM sessions WHERE session_id = '${session_id}'`;
      const sessionResult = await db.executeDirectQuery(sessionQuery);
      
      if (sessionResult.results.length > 0) {
        const session = sessionResult.results[0];
        
  // Does not actually delete session - just marks as "expired"
        const updateQuery = `
          UPDATE sessions 
          SET expires_at = NOW(), data = CONCAT(data, ', "logged_out": true') 
          WHERE session_id = '${session_id}'
        `;
        await db.executeDirectQuery(updateQuery);
        
  // Response leaking session information
        res.json({
          success: true,
          message: 'Logout successful',
          session_info: {
            session_id: session.session_id,
            user_id: session.user_id,
            data: JSON.parse(session.data), // Leaks session data!
            was_admin: session.is_admin,
            duration: new Date() - new Date(session.created_at)
          },
          debug: {
            session_query: sessionQuery, // Leaks query!
            session_still_exists: true, // Admits not deleted!
            update_query: updateQuery
          }
        });
        
      } else {
        res.status(404).json({
          success: false,
          error: 'Session not found',
          debug: {
            searched_session_id: session_id,
            query_executed: sessionQuery,
            hint: 'Session IDs are predictable, try enumerating!'
          }
        });
      }
    } else {
  // Logout without session_id - still accepted
      res.json({
        success: true,
        message: 'Logout successful (no session to invalidate)',
        debug: {
          warning: 'No session_id provided, but logout considered successful',
          token_received: token, // Leaks received token!
          ip: req.ip
        }
      });
    }
    
  } catch (error) {
    logger.error('Logout error:', error);
    
    res.status(500).json({
      success: false,
      error: error.message,
      stack: error.stack
    });
  }
});

// ============================================
// VULNERABLE TOKEN VERIFICATION ENDPOINT
// ============================================
router.post('/verify', (req, res) => {
  try {
    const { token } = req.body;
    
    if (!token) {
      return res.status(400).json({
        success: false,
        error: 'Token required',
        debug: {
          jwt_secret: JWT_SECRET, // VAZA o secret mesmo sem token!
          hint: 'Try generating your own JWT with the secret above'
        }
      });
    }
    
  // Verify JWT without proper validation
    let decoded;
    try {
      decoded = jwt.verify(token, JWT_SECRET);
    } catch (error) {
  // If verification fails, tries to decode without verifying!
      try {
        decoded = jwt.decode(token);
        logger.logSensitive('JWT verification failed, decoding without verification', {
          token,
          decoded,
          error: error.message
        });
      } catch (decodeError) {
        return res.status(401).json({
          success: false,
          error: 'Invalid token',
          debug: {
            jwt_error: error.message,
            decode_error: decodeError.message,
            token_received: token, // Leaks token!
            jwt_secret: JWT_SECRET // Leaks secret!
          }
        });
      }
    }
    
  // Response leaking ALL token information
    res.json({
      success: true,
      message: 'Token valid',
      decoded_payload: decoded, // VAZA payload completo!
      token_info: {
        original_token: token,
        algorithm: 'HS256',
  secret_used: JWT_SECRET, // Leaks secret!
        issued_at: new Date(decoded.iat * 1000),
        expires_at: new Date(decoded.exp * 1000),
        time_until_expiry: decoded.exp * 1000 - Date.now()
      },
      debug: {
        raw_header: jwt.decode(token, { complete: true })?.header,
  signature_valid: true // Falsely claims validation!
      }
    });
    
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message,
      stack: error.stack
    });
  }
});

// ============================================
// VULNERABLE ADMIN ENDPOINT
// ============================================
router.get('/admin/users', async (req, res) => {
  try {
  // No authentication/authorization check!
    
    const { limit, offset, role } = req.query;
    
  // Vulnerable to SQL Injection
    let query = 'SELECT * FROM users';
    if (role) {
      query += ` WHERE role = '${role}'`; // SQL Injection possível!
    }
    if (limit) {
      query += ` LIMIT ${limit}`; // Sem sanitização!
    }
    if (offset) {
      query += ` OFFSET ${offset}`;
    }
    
    const result = await db.executeDirectQuery(query);
    
  // Returns ALL sensitive data of ALL users
    res.json({
      success: true,
      users: result.results, // Includes passwords, SSN, credit cards, etc!
      total_count: result.results.length,
      query_executed: query, // Leaks query!
      debug: {
        warning: 'This endpoint has no authentication!',
        sensitive_data_included: true,
        passwords_exposed: true,
        financial_data_exposed: true
      }
    });
    
    logger.logSensitive('Admin endpoint accessed without auth', {
      query,
      ip: req.ip,
      user_agent: req.get('User-Agent'),
      users_exposed: result.results.length
    });
    
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message,
      stack: error.stack,
      query: req.query
    });
  }
});

module.exports = router;