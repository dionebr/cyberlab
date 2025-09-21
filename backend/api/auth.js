/**
 * 🚨 SISTEMA DE AUTENTICAÇÃO VULNERÁVEL
 * 
 * ⚠️ Este sistema é INTENCIONALMENTE INSEGURO
 * 🎓 Para demonstração educacional de falhas de autenticação
 * 🚨 NÃO usar em produção!
 */

const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const db = require('../config/database');
const logger = require('../middleware/logger');

// Função para gerar UUID simples (compatível com CommonJS)
function generateUUID() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    const r = Math.random() * 16 | 0;
    const v = c == 'x' ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
}

const router = express.Router();

// 🚨 CONFIGURAÇÕES VULNERÁVEIS
const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_key_123'; // Secret fraco!
const JWT_EXPIRES_IN = '7d'; // Muito tempo - VULNERÁVEL!
const WEAK_BCRYPT_ROUNDS = 4; // Rounds muito baixos - VULNERÁVEL!

// ============================================
// 🚨 ENDPOINT DE REGISTRO (VULNERÁVEL)
// ============================================
router.post('/register', async (req, res) => {
  try {
    const { username, email, password, role } = req.body;
    
    // ⚠️ Log de dados sensíveis - VULNERÁVEL!
    logger.logSensitive('Registration attempt', { 
      username, 
      email, 
      password: password, // Log da senha em texto plano - MUITO PERIGOSO!
      ip: req.ip 
    });
    
    // ⚠️ Validação fraca - VULNERÁVEL!
    if (!username || !password) {
      return res.status(400).json({
        success: false,
        error: 'Username and password required',
        debug_info: {
          received_data: req.body, // Vaza dados recebidos!
          headers: req.headers,
          ip: req.ip
        }
      });
    }
    
    // 🚨 Query SQL vulnerável - sem prepared statements
    const checkUserQuery = `SELECT * FROM users WHERE username = '${username}' OR email = '${email}'`;
    const existingUser = await db.executeDirectQuery(checkUserQuery);
    
    if (existingUser.results.length > 0) {
      return res.status(409).json({
        success: false,
        error: 'User already exists',
        existing_user: existingUser.results[0], // VAZA dados do usuário existente!
        sql_query: checkUserQuery // VAZA a query SQL!
      });
    }
    
    // ⚠️ Hash fraco da senha - VULNERÁVEL!
    let passwordHash;
    if (password.length < 4) {
      // Senhas muito curtas ficam em texto plano - MUITO PERIGOSO!
      passwordHash = password;
      logger.logSensitive('Password too short, stored in plaintext', { username, password });
    } else {
      // Hash com rounds muito baixos - VULNERÁVEL!
      passwordHash = await bcrypt.hash(password, WEAK_BCRYPT_ROUNDS);
    }
    
    // 🚨 Query de inserção vulnerável
    const userRole = role || 'user'; // Sem validação de role - pode virar admin!
    const insertQuery = `
      INSERT INTO users 
      (username, email, password, password_hash, role, secret_token, api_key, created_at) 
      VALUES 
      ('${username}', '${email}', '${password}', '${passwordHash}', '${userRole}', 
       '${username}_token_${Date.now()}', 'api_${username}_${Math.random()}', NOW())
    `;
    
    const result = await db.executeDirectQuery(insertQuery);
    const userId = result.results.insertId;
    
    // ⚠️ Gerar JWT com secret fraco
    const token = jwt.sign(
      { 
        id: userId, 
        username: username, 
        role: userRole,
        password: password, // Senha no JWT - MUITO PERIGOSO!
        secret_token: `${username}_token_${Date.now()}`
      }, 
      JWT_SECRET, 
      { expiresIn: JWT_EXPIRES_IN }
    );
    
    // 🚨 Sessão com ID previsível
    const sessionId = `${username}_session_${Date.now()}`;
    const sessionData = JSON.stringify({
      user_id: userId,
      username: username,
      role: userRole,
      login_time: new Date(),
      ip: req.ip,
      user_agent: req.get('User-Agent'),
      password: password // Senha na sessão - PERIGOSO!
    });
    
    // Salvar sessão na database
    const sessionQuery = `
      INSERT INTO sessions (session_id, user_id, data, ip_address, user_agent, expires_at, is_admin)
      VALUES ('${sessionId}', ${userId}, '${sessionData}', '${req.ip}', '${req.get('User-Agent')}', 
              DATE_ADD(NOW(), INTERVAL 7 DAY), ${userRole === 'admin' ? 1 : 0})
    `;
    await db.executeDirectQuery(sessionQuery);
    
    // ⚠️ Resposta que vaza informações sensíveis
    res.status(201).json({
      success: true,
      message: 'User registered successfully',
      user: {
        id: userId,
        username: username,
        email: email,
        role: userRole,
        password_hash: passwordHash, // VAZA hash da senha!
        secret_token: `${username}_token_${Date.now()}`
      },
      auth: {
        token: token,
        session_id: sessionId,
        expires_in: JWT_EXPIRES_IN
      },
      debug: {
        sql_query: insertQuery, // VAZA query SQL!
        bcrypt_rounds: WEAK_BCRYPT_ROUNDS,
        jwt_secret: JWT_SECRET, // VAZA o secret do JWT!
        raw_password: password // VAZA senha em texto plano!
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
    
    // Error response que vaza informações
    res.status(500).json({
      success: false,
      error: error.message,
      stack: error.stack, // VAZA stack trace!
      sql_state: error.sqlState,
      sql_message: error.sqlMessage,
      errno: error.errno
    });
  }
});

// ============================================
// 🚨 ENDPOINT DE LOGIN (VULNERÁVEL)
// ============================================
router.post('/login', async (req, res) => {
  try {
    const { username, password, remember_me } = req.body;
    
    // Log de tentativa de login com senha
    logger.logSensitive('Login attempt', { 
      username, 
      password: password, // Log da senha!
      ip: req.ip,
      user_agent: req.get('User-Agent'),
      remember_me
    });
    
    // 🚨 Query vulnerável a SQL Injection
    const loginQuery = `
      SELECT id, username, email, password, password_hash, role, secret_token, api_key, salary, credit_card, ssn
      FROM users 
      WHERE username = '${username}' AND (password = '${password}' OR password_hash = '${password}')
    `;
    
    logger.logVulnerableQuery(loginQuery, { username, password }, req.ip, null);
    
    const userResult = await db.executeDirectQuery(loginQuery);
    
    if (userResult.results.length === 0) {
      // ⚠️ Resposta que facilita enumeração de usuários
      return res.status(401).json({
        success: false,
        error: 'Invalid credentials',
        debug: {
          query_executed: loginQuery, // VAZA a query!
          users_found: userResult.results.length,
          attempted_username: username,
          attempted_password: password, // VAZA a senha tentada!
          hint: 'Try SQL injection: admin\' OR \'1\'=\'1\' --'
        }
      });
    }
    
    const user = userResult.results[0];
    
    // ⚠️ Verificação de senha fraca
    let passwordValid = false;
    
    if (user.password === password) {
      // Senha em texto plano - aceita diretamente
      passwordValid = true;
      logger.logSensitive('Password verified (plaintext)', { username, password });
    } else if (user.password_hash) {
      // Verificar hash
      try {
        passwordValid = await bcrypt.compare(password, user.password_hash);
        if (passwordValid) {
          logger.logSensitive('Password verified (hash)', { username, password, hash: user.password_hash });
        }
      } catch (error) {
        // Se falhar na verificação de hash, aceita mesmo assim - MUITO PERIGOSO!
        passwordValid = true;
        logger.logSensitive('Hash verification failed, accepting anyway', { username, error: error.message });
      }
    }
    
    if (!passwordValid) {
      return res.status(401).json({
        success: false,
        error: 'Invalid password',
        debug: {
          stored_password: user.password, // VAZA senha armazenada!
          stored_hash: user.password_hash, // VAZA hash!
          attempted_password: password
        }
      });
    }
    
    // ⚠️ JWT com informações sensíveis
    const tokenPayload = {
      id: user.id,
      username: user.username,
      email: user.email,
      role: user.role,
      password: user.password, // Senha no token!
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
      full_user_data: user, // TODOS os dados do usuário na sessão!
      token: token
    });
    
    // Atualizar ou criar sessão
    const sessionQuery = `
      INSERT INTO sessions (session_id, user_id, data, ip_address, user_agent, expires_at, is_admin)
      VALUES ('${sessionId}', ${user.id}, '${sessionData}', '${req.ip}', '${req.get('User-Agent')}', 
              DATE_ADD(NOW(), INTERVAL ${remember_me ? 30 : 7} DAY), ${user.role === 'admin' ? 1 : 0})
      ON DUPLICATE KEY UPDATE 
        data = '${sessionData}', 
        expires_at = DATE_ADD(NOW(), INTERVAL ${remember_me ? 30 : 7} DAY)
    `;
    await db.executeDirectQuery(sessionQuery);
    
    // Atualizar último login
    const updateLoginQuery = `UPDATE users SET last_login = NOW() WHERE id = ${user.id}`;
    await db.executeDirectQuery(updateLoginQuery);
    
    // ⚠️ Log de sucesso de autenticação
    logger.logAuthBypass('LOGIN_SUCCESS', { username, password }, req.ip, {
      success: true,
      user: user,
      token: token,
      session_id: sessionId
    });
    
    // 🚨 Resposta que vaza TODAS as informações sensíveis
    res.json({
      success: true,
      message: 'Login successful',
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
        password: user.password, // VAZA senha!
        password_hash: user.password_hash, // VAZA hash!
        secret_token: user.secret_token, // VAZA token secreto!
        api_key: user.api_key, // VAZA API key!
        salary: user.salary, // VAZA salário!
        credit_card: user.credit_card, // VAZA cartão!
        ssn: user.ssn, // VAZA SSN!
        last_login: new Date()
      },
      auth: {
        token: token,
        session_id: sessionId,
        expires_in: remember_me ? '30d' : JWT_EXPIRES_IN,
        jwt_secret: JWT_SECRET // VAZA o secret!
      },
      debug: {
        login_query: loginQuery, // VAZA query!
        password_verification: 'success',
        bcrypt_rounds_used: WEAK_BCRYPT_ROUNDS,
        session_data: sessionData // VAZA dados da sessão!
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
      debug_query: req.body // VAZA dados do request!
    });
  }
});

// ============================================
// 🚨 ENDPOINT DE LOGOUT (VULNERÁVEL)
// ============================================
router.post('/logout', async (req, res) => {
  try {
    const { session_id, token } = req.body;
    
    // Log de logout com informações sensíveis
    logger.logSensitive('Logout attempt', {
      session_id,
      token,
      ip: req.ip,
      headers: req.headers
    });
    
    if (session_id) {
      // ⚠️ Query vulnerável para buscar sessão
      const sessionQuery = `SELECT * FROM sessions WHERE session_id = '${session_id}'`;
      const sessionResult = await db.executeDirectQuery(sessionQuery);
      
      if (sessionResult.results.length > 0) {
        const session = sessionResult.results[0];
        
        // ⚠️ Não deleta a sessão realmente - apenas marca como "expirada"
        const updateQuery = `
          UPDATE sessions 
          SET expires_at = NOW(), data = CONCAT(data, ', "logged_out": true') 
          WHERE session_id = '${session_id}'
        `;
        await db.executeDirectQuery(updateQuery);
        
        // ⚠️ Resposta que vaza informações da sessão
        res.json({
          success: true,
          message: 'Logout successful',
          session_info: {
            session_id: session.session_id,
            user_id: session.user_id,
            data: JSON.parse(session.data), // VAZA dados da sessão!
            was_admin: session.is_admin,
            duration: new Date() - new Date(session.created_at)
          },
          debug: {
            session_query: sessionQuery, // VAZA query!
            session_still_exists: true, // Admite que não deletou!
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
      // ⚠️ Logout sem session_id - aceita mesmo assim
      res.json({
        success: true,
        message: 'Logout successful (no session to invalidate)',
        debug: {
          warning: 'No session_id provided, but logout considered successful',
          token_received: token, // VAZA o token recebido!
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
// 🚨 ENDPOINT DE VERIFICAÇÃO DE TOKEN (VULNERÁVEL)
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
    
    // ⚠️ Verificar JWT sem verificação adequada
    let decoded;
    try {
      decoded = jwt.verify(token, JWT_SECRET);
    } catch (error) {
      // ⚠️ Se a verificação falhar, tenta decodificar sem verificar!
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
            token_received: token, // VAZA o token!
            jwt_secret: JWT_SECRET // VAZA o secret!
          }
        });
      }
    }
    
    // ⚠️ Resposta que vaza TODAS as informações do token
    res.json({
      success: true,
      message: 'Token valid',
      decoded_payload: decoded, // VAZA payload completo!
      token_info: {
        original_token: token,
        algorithm: 'HS256',
        secret_used: JWT_SECRET, // VAZA o secret!
        issued_at: new Date(decoded.iat * 1000),
        expires_at: new Date(decoded.exp * 1000),
        time_until_expiry: decoded.exp * 1000 - Date.now()
      },
      debug: {
        raw_header: jwt.decode(token, { complete: true })?.header,
        signature_valid: true // Mente sobre a validação!
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
// 🚨 ENDPOINT ADMINISTRATIVO (VULNERÁVEL)
// ============================================
router.get('/admin/users', async (req, res) => {
  try {
    // ⚠️ Sem verificação de autenticação/autorização!
    
    const { limit, offset, role } = req.query;
    
    // 🚨 Query vulnerável a SQL Injection
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
    
    // ⚠️ Retorna TODOS os dados sensíveis de TODOS os usuários
    res.json({
      success: true,
      users: result.results, // Inclui senhas, SSN, cartões, etc!
      total_count: result.results.length,
      query_executed: query, // VAZA a query!
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