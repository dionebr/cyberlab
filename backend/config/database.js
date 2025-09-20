/**
 * 🚨 CONFIGURAÇÃO DE DATABASE VULNERÁVEL
 * 
 * ⚠️ Esta configuração é INTENCIONALMENTE INSEGURA
 * 🎓 Para fins educacionais em segurança cibernética
 * 🚨 NÃO usar em produção!
 */

const mysql = require('mysql2');
const fs = require('fs');
const path = require('path');
const logger = require('../middleware/logger');

// 🚨 CONFIGURAÇÕES VULNERÁVEIS - NÃO usar em produção!
const dbConfig = {
  host: process.env.DB_HOST || 'localhost',
  port: process.env.DB_PORT || 3306,
  user: process.env.DB_USER || 'vulnerable_user',
  password: process.env.DB_PASS || 'weak123', // Senha fraca
  database: process.env.DB_NAME || 'cyberlab_vulnerable',
  charset: 'utf8mb4',
  
  // CONFIGURAÇÕES PERIGOSAS:
  ssl: false, // SSL DESABILITADO - VULNERÁVEL
  insecureAuth: true, // Permite autenticação insegura
  acquireTimeout: 60000,
  timeout: 60000,
  reconnect: true,
  
  // Configurações para múltiplas queries (SQL Injection)
  multipleStatements: true, // PERIGOSO! Permite múltiplas queries
  
  // Pool de conexões com configurações frouxas
  connectionLimit: 100,
  queueLimit: 0,
  
  // Flags perigosas
  flags: [
    'FOUND_ROWS',
    'LONG_PASSWORD',
    'LONG_FLAG',
    'TRANSACTIONS',
    'PROTOCOL_41',
    'SECURE_CONNECTION'
  ]
};

// Criar pool de conexões (sem SSL)
const pool = mysql.createPool(dbConfig);

// Função para executar queries SEM prepared statements - VULNERÁVEL!
const executeVulnerableQuery = (query, params = []) => {
  return new Promise((resolve, reject) => {
    // VULNERÁVEL: String concatenation em vez de prepared statements
    const finalQuery = typeof params === 'object' && params.length > 0
      ? query.replace(/\?/g, () => `'${params.shift()}'`) // PERIGOSO!
      : query;
    
    logger.warn(`🚨 Executing VULNERABLE query: ${finalQuery}`);
    
    pool.execute(finalQuery, (error, results, fields) => {
      if (error) {
        logger.error('Query error:', error);
        reject(error);
      } else {
        resolve({ results, fields });
      }
    });
  });
};

// Função para executar queries diretas (muito vulnerável)
const executeDirectQuery = (query) => {
  return new Promise((resolve, reject) => {
    logger.warn(`🚨 Executing DIRECT query (VERY DANGEROUS): ${query}`);
    
    pool.query(query, (error, results, fields) => {
      if (error) {
        logger.error('Direct query error:', error);
        reject(error);
      } else {
        resolve({ results, fields, query });
      }
    });
  });
};

// Testar conexão
const testConnection = () => {
  return new Promise((resolve, reject) => {
    pool.getConnection((err, connection) => {
      if (err) {
        logger.error('Database connection failed:', err);
        reject(err);
      } else {
        logger.info('💀 Database connected successfully (WITHOUT SSL)');
        connection.release();
        resolve();
      }
    });
  });
};

// Inicializar dados vulneráveis
const initVulnerableData = async () => {
  try {
    logger.info('🚨 Initializing vulnerable database schema and data...');
    
    // Ler e executar script de inicialização
    const initScript = fs.readFileSync(
      path.join(__dirname, 'init.sql'), 
      'utf8'
    );
    
    // Executar múltiplas queries de uma vez - VULNERÁVEL
    await executeDirectQuery(initScript);
    
    // Inserir dados vulneráveis
    const mockDataScript = fs.readFileSync(
      path.join(__dirname, 'mock-data.sql'),
      'utf8'
    );
    
    await executeDirectQuery(mockDataScript);
    
    logger.info('✅ Vulnerable database initialized successfully');
    
  } catch (error) {
    logger.error('Failed to initialize vulnerable database:', error);
    throw error;
  }
};

// Função para obter informações sensíveis do DB - VULNERÁVEL
const getDatabaseInfo = async () => {
  try {
    const info = await executeDirectQuery(`
      SELECT 
        VERSION() as version,
        USER() as current_user,
        DATABASE() as current_database,
        @@hostname as hostname,
        @@port as port,
        @@basedir as base_directory,
        @@datadir as data_directory,
        @@socket as socket,
        @@ssl_disabled as ssl_status
    `);
    
    return info.results[0];
  } catch (error) {
    logger.error('Failed to get database info:', error);
    return null;
  }
};

// Função para listar todas as tabelas - VULNERÁVEL
const getAllTables = async () => {
  try {
    const tables = await executeDirectQuery('SHOW TABLES');
    return tables.results;
  } catch (error) {
    logger.error('Failed to get tables:', error);
    return [];
  }
};

// Função para descrever estrutura de tabela - VULNERÁVEL  
const describeTable = async (tableName) => {
  try {
    // VULNERÁVEL: Sem validação do nome da tabela
    const structure = await executeDirectQuery(`DESCRIBE ${tableName}`);
    return structure.results;
  } catch (error) {
    logger.error(`Failed to describe table ${tableName}:`, error);
    return [];
  }
};

// Função para fechar conexões
const close = () => {
  pool.end((err) => {
    if (err) {
      logger.error('Error closing database pool:', err);
    } else {
      logger.info('Database pool closed');
    }
  });
};

// Export das funções vulneráveis
module.exports = {
  pool,
  
  // Funções VULNERÁVEIS para educational hacking
  executeVulnerableQuery,
  executeDirectQuery,
  
  // Funções de utilidade
  testConnection,
  initVulnerableData,
  getDatabaseInfo,
  getAllTables,
  describeTable,
  close,
  
  // Configurações expostas (VULNERÁVEL)
  config: dbConfig
};