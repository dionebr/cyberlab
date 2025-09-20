/**
 * 🚨 ENDPOINTS VULNERÁVEIS DE INJEÇÃO SQL
 * 
 * ⚠️ Estes endpoints são INTENCIONALMENTE VULNERÁVEIS
 * 🎓 Para demonstração educacional de SQL Injection
 * 🚨 NÃO usar em produção!
 */

const express = require('express');
const db = require('../config/database');
const logger = require('../middleware/logger');
const { vulnerableAuth, requireRole } = require('../middleware/auth');

const router = express.Router();

// ============================================
// 🚨 BUSCA DE USUÁRIOS - SQL INJECTION BÁSICO
// ============================================
router.get('/users/search', async (req, res) => {
  try {
    const { username, email, role } = req.query;
    
    logger.logSensitive('User search attempt', { username, email, role, ip: req.ip });
    
    // 🚨 Query vulnerável a SQL Injection
    let query = 'SELECT * FROM users WHERE 1=1';
    
    if (username) {
      query += ` AND username LIKE '%${username}%'`; // VULNERÁVEL!
    }
    
    if (email) {
      query += ` AND email = '${email}'`; // VULNERÁVEL!
    }
    
    if (role) {
      query += ` AND role = '${role}'`; // VULNERÁVEL!
    }
    
    logger.logVulnerableQuery(query, { username, email, role }, req.ip, null);
    
    const result = await db.executeDirectQuery(query);
    
    res.json({
      success: true,
      users: result.results,
      total: result.results.length,
      query_executed: query, // VAZA a query!
      debug: {
        hint: "Try: ?username=admin' OR '1'='1' --",
        examples: [
          "?username=' UNION SELECT * FROM users --",
          "?email=' OR 1=1 --",
          "?role=' OR role='admin' --"
        ]
      }
    });
    
  } catch (error) {
    logger.error('User search error:', error);
    
    res.status(500).json({
      success: false,
      error: error.message,
      sql_error: error.sqlMessage,
      errno: error.errno,
      sql_state: error.sqlState
    });
  }
});

// ============================================
// 🚨 DETALHES DO USUÁRIO - SQL INJECTION
// ============================================
router.get('/users/:id', async (req, res) => {
  try {
    const { id } = req.params;
    
    // 🚨 Query vulnerável - parâmetro direto na query
    const query = `
      SELECT u.*, p.profile_data, s.session_data, l.activity_log
      FROM users u
      LEFT JOIN user_profiles p ON u.id = p.user_id
      LEFT JOIN sessions s ON u.id = s.user_id
      LEFT JOIN activity_logs l ON u.id = l.user_id
      WHERE u.id = ${id}
    `;
    
    logger.logVulnerableQuery(query, { id }, req.ip, null);
    
    const result = await db.executeDirectQuery(query);
    
    if (result.results.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'User not found',
        query_executed: query,
        debug: {
          hint: "Try: /users/1 OR 1=1",
          union_example: "/users/1 UNION SELECT password,email,role,ssn,credit_card FROM users"
        }
      });
    }
    
    res.json({
      success: true,
      user: result.results[0],
      all_data: result.results,
      query_executed: query,
      debug: {
        sensitive_data_included: true,
        warning: 'All user data exposed!'
      }
    });
    
  } catch (error) {
    logger.error('User details error:', error);
    
    res.status(500).json({
      success: false,
      error: error.message,
      sql_error: error.sqlMessage,
      stack: error.stack,
      query: req.params
    });
  }
});

// ============================================
// 🚨 ATUALIZAÇÃO DE PERFIL - SQL INJECTION
// ============================================
router.post('/users/update-profile', vulnerableAuth, async (req, res) => {
  try {
    const { user_id, field, value } = req.body;
    
    logger.logSensitive('Profile update attempt', { 
      user_id, 
      field, 
      value,
      authenticated_user: req.user,
      ip: req.ip 
    });
    
    // 🚨 Query de update vulnerável
    const updateQuery = `
      UPDATE users 
      SET ${field} = '${value}', updated_at = NOW() 
      WHERE id = ${user_id}
    `;
    
    logger.logVulnerableQuery(updateQuery, { user_id, field, value }, req.ip, req.user);
    
    const result = await db.executeDirectQuery(updateQuery);
    
    // Buscar dados atualizados
    const selectQuery = `SELECT * FROM users WHERE id = ${user_id}`;
    const userData = await db.executeDirectQuery(selectQuery);
    
    res.json({
      success: true,
      message: 'Profile updated successfully',
      affected_rows: result.results.affectedRows,
      updated_user: userData.results[0],
      queries_executed: {
        update: updateQuery,
        select: selectQuery
      },
      debug: {
        hint: "Try: field=role,password,salary&value=admin where id=1 or 1=1",
        warning: 'Any field can be updated without validation!'
      }
    });
    
  } catch (error) {
    logger.error('Profile update error:', error);
    
    res.status(500).json({
      success: false,
      error: error.message,
      sql_error: error.sqlMessage,
      errno: error.errno
    });
  }
});

// ============================================
// 🚨 RELATÓRIOS AVANÇADOS - UNION SQL INJECTION
// ============================================
router.get('/reports/user-stats', requireRole('admin'), async (req, res) => {
  try {
    const { 
      start_date, 
      end_date, 
      department, 
      salary_range,
      order_by = 'username',
      limit = 100 
    } = req.query;
    
    // 🚨 Query complexa vulnerável
    let query = `
      SELECT 
        username, 
        email, 
        role, 
        salary, 
        department, 
        credit_card,
        ssn,
        created_at,
        last_login,
        (SELECT COUNT(*) FROM activity_logs WHERE user_id = users.id) as activity_count
      FROM users 
      WHERE 1=1
    `;
    
    if (start_date) {
      query += ` AND created_at >= '${start_date}'`;
    }
    
    if (end_date) {
      query += ` AND created_at <= '${end_date}'`;
    }
    
    if (department) {
      query += ` AND department = '${department}'`;
    }
    
    if (salary_range) {
      query += ` AND salary ${salary_range}`;
    }
    
    query += ` ORDER BY ${order_by}`;
    query += ` LIMIT ${limit}`;
    
    logger.logVulnerableQuery(query, req.query, req.ip, req.user);
    
    const result = await db.executeDirectQuery(query);
    
    res.json({
      success: true,
      stats: result.results,
      total_records: result.results.length,
      query_executed: query,
      parameters_used: req.query,
      debug: {
        union_injection_example: "?order_by=username UNION SELECT password,ssn,credit_card,api_key,secret_token,role,'','','' FROM users--",
        advanced_examples: [
          "?department=' OR role='admin' --",
          "?salary_range=> 0 UNION SELECT * FROM admin_secrets --",
          "?limit=1; DROP TABLE users; --"
        ],
        warning: "All financial and personal data exposed!"
      }
    });
    
  } catch (error) {
    logger.error('Report generation error:', error);
    
    res.status(500).json({
      success: false,
      error: error.message,
      sql_error: error.sqlMessage,
      stack: error.stack
    });
  }
});

// ============================================
// 🚨 BUSCA DE LOGS - BLIND SQL INJECTION
// ============================================
router.get('/logs/search', vulnerableAuth, async (req, res) => {
  try {
    const { 
      user_id, 
      action, 
      date_filter, 
      sensitive = false,
      timeout = 5000 
    } = req.query;
    
    // 🚨 Simulação de Blind SQL Injection com timeouts
    let query = `
      SELECT 
        l.*,
        u.username,
        u.email,
        u.role,
        CASE WHEN l.sensitive_data IS NOT NULL THEN 'HAS_SENSITIVE_DATA' ELSE 'NO_SENSITIVE_DATA' END as data_flag
      FROM activity_logs l
      JOIN users u ON l.user_id = u.id
      WHERE 1=1
    `;
    
    if (user_id) {
      // ⚠️ Condição que pode causar delay para demonstrar Blind SQL Injection
      query += ` AND (
        l.user_id = ${user_id} 
        ${sensitive === 'true' ? `OR (SELECT SLEEP(${timeout/1000}) FROM users WHERE id = ${user_id} AND password LIKE '%admin%')` : ''}
      )`;
    }
    
    if (action) {
      query += ` AND l.action LIKE '%${action}%'`;
    }
    
    if (date_filter) {
      query += ` AND l.created_at ${date_filter}`;
    }
    
    query += ` ORDER BY l.created_at DESC LIMIT 50`;
    
    logger.logVulnerableQuery(query, req.query, req.ip, req.user);
    
    const startTime = Date.now();
    const result = await db.executeDirectQuery(query);
    const executionTime = Date.now() - startTime;
    
    res.json({
      success: true,
      logs: result.results,
      execution_time_ms: executionTime,
      query_executed: query,
      debug: {
        blind_injection_hint: "Use ?user_id=1 AND (SELECT SLEEP(5) WHERE (SELECT password FROM users WHERE id=1) LIKE 'a%')",
        time_based_examples: [
          "?user_id=1; SELECT IF(SUBSTRING((SELECT password FROM users WHERE id=1),1,1)='a', SLEEP(5), 0)",
          "?sensitive=true&user_id=1 (triggers conditional SLEEP)",
          "?date_filter=> '2024-01-01' AND (SELECT SLEEP(3) WHERE 1=1)"
        ],
        execution_time_note: `Query took ${executionTime}ms - monitor for unusual delays`
      }
    });
    
  } catch (error) {
    logger.error('Log search error:', error);
    
    res.status(500).json({
      success: false,
      error: error.message,
      sql_error: error.sqlMessage
    });
  }
});

// ============================================
// 🚨 OPERAÇÕES EM LOTE - STACKED QUERIES
// ============================================
router.post('/admin/batch-operations', requireRole('admin'), async (req, res) => {
  try {
    const { operation, target_table, conditions, new_values } = req.body;
    
    logger.logSensitive('Batch operation request', { 
      operation, 
      target_table, 
      conditions, 
      new_values,
      user: req.user,
      ip: req.ip 
    });
    
    let query = '';
    
    // 🚨 Construção de query baseada no tipo de operação - MUITO PERIGOSO!
    switch(operation) {
      case 'update':
        query = `UPDATE ${target_table} SET ${new_values} WHERE ${conditions}`;
        break;
        
      case 'delete':
        query = `DELETE FROM ${target_table} WHERE ${conditions}`;
        break;
        
      case 'select':
        query = `SELECT * FROM ${target_table} WHERE ${conditions}`;
        break;
        
      case 'custom':
        // ⚠️ Execução de query customizada - EXTREMAMENTE PERIGOSO!
        query = req.body.custom_query || 'SELECT 1';
        break;
        
      default:
        query = `SELECT COUNT(*) as count FROM ${target_table} WHERE ${conditions}`;
    }
    
    // ⚠️ Log da query antes da execução
    logger.logVulnerableQuery(query, req.body, req.ip, req.user);
    
    // 🚨 Execução direta - permite stacked queries!
    const result = await db.executeDirectQuery(query);
    
    res.json({
      success: true,
      operation_completed: operation,
      affected_rows: result.results.affectedRows || result.results.length,
      data: result.results,
      query_executed: query,
      debug: {
        stacked_query_example: "custom_query=SELECT * FROM users; DROP TABLE logs; INSERT INTO users VALUES ('hacker','hack@evil.com','admin')",
        dangerous_operations: [
          "operation=custom&custom_query=SHOW DATABASES",
          "operation=custom&custom_query=SELECT * FROM information_schema.tables",
          "operation=delete&target_table=users&conditions=1=1",
          "new_values=password='hacked'&target_table=users&conditions=role='admin'"
        ],
        warning: "This endpoint allows arbitrary SQL execution!"
      }
    });
    
  } catch (error) {
    logger.error('Batch operation error:', error);
    
    res.status(500).json({
      success: false,
      error: error.message,
      sql_error: error.sqlMessage,
      executed_query: req.body
    });
  }
});

module.exports = router;